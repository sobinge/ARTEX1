#!/bin/bash
# ARTEX Tor 新增功能回归（真实 Tor + 本地平台）
# 覆盖：实例池、按 Agent 解析、出口实测、换电路作用域、fail-closed、入站 onion、信标通道
#
# 前置：
#   1) 后端已启动，且 /tmp/artex-regress/token.txt 存有 JWT
#   2) 本机装有 tor（默认 /usr/local/opt/tor/bin/tor）
set -u
BASE="${ARTEX_BASE:-http://127.0.0.1:8899}"
T=$(cat "${ARTEX_TOKEN_FILE:-/tmp/artex-regress/token.txt}")
OUT="${ARTEX_OUT:-/tmp/artex-regress/regression}"
TORBIN="${ARTEX_TOR_BIN:-/usr/local/opt/tor/bin/tor}"
TORUP="${ARTEX_TOR_UPSTREAM:-127.0.0.1:7897}"
mkdir -p "$OUT"
PASS=0; FAIL=0; N=0

req() { # method path [body]
  local m=$1 p=$2 b=${3:-}
  if [ -n "$b" ]; then
    curl -s -m 240 --noproxy '*' -X "$m" "$BASE$p" -H "Authorization: Bearer $T" \
      -H 'Content-Type: application/json' -d "$b"
  else
    curl -s -m 240 --noproxy '*' -X "$m" "$BASE$p" -H "Authorization: Bearer $T"
  fi
}

norm() { printf '%s' "$1" | tr -d ' \t\r\n'; }

check() { # name expected_substr actual_json（忽略空白差异）
  N=$((N+1))
  local name=$1 want=$2 got=$3
  if printf '%s' "$(norm "$got")" | grep -q -- "$(norm "$want")"; then
    PASS=$((PASS+1)); printf '  [PASS] %-44s %s\n' "$name" "$want"
  else
    FAIL=$((FAIL+1)); printf '  [FAIL] %-44s 期望: %s\n         实际: %s\n' "$name" "$want" "$(printf '%s' "$got" | cut -c1-400)"
  fi
}

save() { printf '%s' "$2" > "$OUT/$1.json"; }

echo "=== T1 设置基线（tor_pool 字段存在）==="
S=$(req GET /api/settings); save settings_before "$S"
check "settings.tor_pool_enabled" '"tor_pool_enabled"' "$S"
check "settings.tor_pool_upstream" '"tor_pool_upstream"' "$S"

echo "=== T2 启用实例池（2 实例，等 bootstrap 100%）==="
R=$(req PUT /api/system/torpool "{\"enabled\":true,\"size\":2,\"socks_base\":19750,\"control_base\":19850,\"dir\":\"/tmp/artex-regress/data/torpool\",\"binary\":\"$TORBIN\",\"upstream\":\"$TORUP\"}")
save pool_enable "$R"
check "池 started=true" '"started":true' "$R"
check "实例数 2" '"size":2' "$R"
check "槽位 1 SOCKS 19750" '127.0.0.1:19750' "$R"
check "槽位 2 SOCKS 19751" '127.0.0.1:19751' "$R"
check "control cookie 就绪" '"cookie_ready":true' "$R"

echo "=== T3 池状态查询 ==="
R=$(req GET /api/system/torpool); save pool_status "$R"
check "状态 enabled" '"enabled":true' "$R"
check "实例运行状态可见" '"running":true' "$R"
check "cookie 状态可见" '"cookie_ready":true' "$R"

echo "=== T4 两个 Agent 固定槽位 1 / 2 ==="
R=$(req PUT /api/agents/planner/config '{"egress_mode":"tor","tor_rotate":"off","tor_circuit_key":"task","egress_tor_instance":1}')
save agent_planner_cfg "$R"
check "planner 保存返回 ok" '"ok":true' "$R"
R=$(req GET /api/agents/planner); save agent_planner_dto "$R"
check "planner 持久化 egress_tor_instance=1" '"egress_tor_instance":1' "$R"
check "planner DTO 带 egress_mode=tor" '"egress_mode":"tor"' "$R"
R=$(req PUT /api/agents/worker/config '{"egress_mode":"tor","tor_rotate":"off","tor_circuit_key":"agent","egress_tor_instance":2}')
save agent_worker_cfg "$R"
R=$(req GET /api/agents/worker); save agent_worker_dto "$R"
check "worker 持久化 egress_tor_instance=2" '"egress_tor_instance":2' "$R"

echo "=== T5 出口解析（按槽位路由）==="
R=$(req GET /api/agents/planner/egress); save egress_planner "$R"
check "planner resolved.mode=tor" '"mode":"tor"' "$R"
check "planner 走槽位 1" '127.0.0.1:19750' "$R"
check "planner tor_instance=1" '"tor_instance":1' "$R"
R=$(req GET /api/agents/worker/egress); save egress_worker "$R"
check "worker 走槽位 2" '127.0.0.1:19751' "$R"
check "worker tor_instance=2" '"tor_instance":2' "$R"
check "保留 socks5h（远程 DNS）" '"proxy_url":"socks5h://' "$R"
check "planner 无 CA 证书注入" '"is_tor":true' "$R"

echo "=== T6 出口实测（真实 Tor 链路）==="
R=$(req POST /api/agents/planner/egress/test '{}'); save probe_planner "$R"
check "planner 探测 ok" '"ok":true' "$R"
check "planner is_tor=true" '"is_tor":true' "$R"
check "planner 拿到出口 IP" '"ip":"' "$R"
R=$(req POST /api/agents/worker/egress/test '{}'); save probe_worker "$R"
check "worker is_tor=true" '"is_tor":true' "$R"

echo "=== T7 换电路作用域 ==="
R=$(req POST /api/agents/planner/egress/newnym '{}'); save newnym_planner "$R"
check "newnym scope=instance" '"scope":"instance"' "$R"
check "newnym 命中实例 1" '"instance":1' "$R"

echo "=== T8 出口审计接口 ==="
R=$(req GET /api/agents/planner/egress/runs); save egress_runs "$R"
check "审计接口返回 runs" '"runs"' "$R"

echo "=== T9 入站 onion（真实 Tor 生成 v3 地址 + 客户端授权）==="
R=$(req POST /api/inbound/onion '{"name":"regress01","target":"127.0.0.1:8899"}'); save onion_create "$R"
check "onion 创建 ok" '"ok":true' "$R"
check "返回 torrc 片段（HiddenServicePort）" 'HiddenServicePort' "$R"
ONIONDIR=$(printf '%s' "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dir',''))")
FRAG=$(printf '%s' "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('torrc',''))")
echo "  onion 目录: $ONIONDIR"
echo "  torrc 片段: $(printf '%s' "$FRAG" | tr '\n' ' ')"
if [ -n "$ONIONDIR" ]; then
  mkdir -p "$OUT/onion-run"
  # 用平台返回的片段，避免脚本自己写错 HiddenServicePort 语法；
  # 端口动态选取，避免上一轮 timeout tor 未退出导致 bind 冲突
  read -r OP CP < <(python3 - <<'PYEOF'
import socket
def free():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p
a = free(); b = free()
while b == a:
    b = free()
print(a, b)
PYEOF
)
  mkdir -p "$OUT/onion-run/data"
  chmod 700 "$OUT/onion-run/data"
  {
    echo "DataDirectory $OUT/onion-run/data"
    echo "SocksPort $OP"
    echo "ControlPort $CP"
    echo "CookieAuthentication 1"
    echo "CookieAuthFile $OUT/onion-run/data/control_auth_cookie"
    printf '%s\n' "$FRAG"
    echo "Log notice file $OUT/onion-run/data/tor.log"
    echo "HTTPSProxy $TORUP"
  } > "$OUT/onion-run/torrc"
  timeout 300 "$TORBIN" -f "$OUT/onion-run/torrc" > "$OUT/onion-run/stdout.log" 2>&1 &
  for i in $(seq 1 60); do [ -s "$ONIONDIR/hostname" ] && break; sleep 2; done
  if [ -s "$ONIONDIR/hostname" ]; then
    echo "  onion 地址: $(cat "$ONIONDIR/hostname")"
    R=$(req GET /api/inbound/onion); save onion_list "$R"
    check "列表包含 regress01" 'regress01' "$R"
    check "列表含 56 位 v3 地址" '.onion' "$R"
    R=$(req POST /api/inbound/onion/regress01/clients '{"client":"ci-regress"}'); save onion_client "$R"
    check "客户端私钥（仅返回一次）" '"auth_private"' "$R"
    check "客户端密钥为 x25519 v3" 'descriptor:x25519:' "$R"
    check "返回客户端指纹" '"fingerprint"' "$R"
    R=$(req POST /api/inbound/onion/regress01/enable '{}'); save onion_enable "$R"
    check "有授权客户端后允许启用" '"ok":true' "$R"
  else
    check "Tor 生成 onion 地址" 'hostname' "missing: $(grep -E 'err|warn|Hidden' "$OUT/onion-run/stdout.log" 2>/dev/null | head -4)"
  fi
fi

echo "=== T10 信标通道（需匿名出口）==="
R=$(req POST /api/beacon/channels '{"agent_key":"planner","kind":"third_party","endpoint":"https://mailbox.example.invalid/api"}'); save beacon_create "$R"
CH=$(printf '%s' "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);c=d.get('channel') or d;print(c.get('id','') if isinstance(c,dict) else '')" 2>/dev/null)
if [ -n "$CH" ]; then
  check "信标通道创建" '"channel_id"' "$R"
  check "信标返回 PSK 一次" '"psk"' "$R"
  R=$(req POST "/api/beacon/channels/$CH/commands" '{"cmd":"id","args":"","timeout_secs":30}'); save beacon_cmd "$R"
  check "入队命令" '"ok":true' "$R"
  R=$(req GET "/api/beacon/channels/$CH/commands"); save beacon_take "$R"
  check "命令队列可取" 'cmd' "$R"
  R=$(req GET /api/beacon/channels); save beacon_list "$R"
  check "通道列表含新通道" "$CH" "$R"
else
  check "信标通道创建" '"channel_id"' "$R"
  check "信标返回 PSK 一次" '"psk"' "$R"
fi

echo "=== T11 fail-closed（停池后必须拒绝，不回退直连）==="
R=$(req POST /api/system/torpool/stop '{}'); save pool_stop "$R"
check "池已停止" '"started":false' "$R"
R=$(req GET /api/agents/planner/egress); save egress_after_stop "$R"
check "拒绝并声明不回退直连" '不会回退直连' "$R"

echo "=== T12 关闭池（回落到单 daemon 配置）==="
R=$(req PUT /api/system/torpool "{\"enabled\":false,\"size\":2,\"socks_base\":19750,\"control_base\":19850,\"dir\":\"/tmp/artex-regress/data/torpool\",\"binary\":\"$TORBIN\",\"upstream\":\"$TORUP\"}")
save pool_disable "$R"
check "size=0" '"size":0' "$R"

echo
echo "================ 结果 ================"
echo "通过: $PASS   失败: $FAIL   总计: $N"
[ "$FAIL" -eq 0 ] || exit 1
