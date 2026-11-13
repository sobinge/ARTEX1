"use client";

import * as React from "react";

import { ArrowDownIcon, ArrowUpIcon, PlusIcon, RefreshCwIcon, RouteIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type {
  EgressProvider,
  EgressRoutingAudit,
  EgressRoutingConfig,
  EgressRoutingRule,
  EgressRoutingStatus,
  EgressRoutingTestResult,
  EgressRuleType,
} from "@/lib/types";

const DEFAULT_CONFIG: EgressRoutingConfig = {
  rules: [],
  fallback: { enabled: false, failure_threshold: 3, cooldown_seconds: 300 },
  clash_proxy: "http://127.0.0.1:7890",
};

function providerName(provider?: string): string {
  if (provider === "tor") return "Tor";
  if (provider === "clash") return "Clash";
  if (provider === "direct") return "平台例外";
  if (provider === "proxy") return "自定义代理";
  if (provider === "inherit") return "继承目标规则";
  return provider ?? "—";
}

function reasonName(reason?: string): string {
  const names: Record<string, string> = {
    "default-tor": "默认使用 Tor",
    "explicit-tor": "明确指定 Tor",
    "explicit-clash": "明确指定 Clash",
    "explicit-proxy": "明确指定自定义代理",
    "target-rule": "命中目标规则",
    "tor-fallback-cooldown": "冷却期内继续使用 Clash",
    "tor-failure-threshold": "Tor 失败达到阈值，切换 Clash",
    "platform-exception": "命中平台白名单",
    "manual-task-switch": "手动切换任务出口",
    "manual-agent-switch": "手动切换 Agent 出口",
    "target-rules-updated": "更新目标路由规则",
  };
  if (!reason) return "—";
  return names[reason] ?? reason;
}

function timestamp(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString();
}

export function EgressRoutingCard() {
  const [config, setConfig] = React.useState<EgressRoutingConfig>(DEFAULT_CONFIG);
  const [status, setStatus] = React.useState<EgressRoutingStatus | null>(null);
  const [statusFetchedAt, setStatusFetchedAt] = React.useState(0);
  const [events, setEvents] = React.useState<EgressRoutingAudit[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [loadError, setLoadError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  const [threshold, setThreshold] = React.useState("3");
  const [cooldown, setCooldown] = React.useState("300");
  const [testMode, setTestMode] = React.useState<"inherit" | "tor" | "clash">("inherit");
  const [testURL, setTestURL] = React.useState("https://check.torproject.org/api/ip");
  const [testTask, setTestTask] = React.useState("");
  const [testAgent, setTestAgent] = React.useState("worker");
  const [testing, setTesting] = React.useState(false);
  const [testResult, setTestResult] = React.useState<EgressRoutingTestResult | null>(null);

  const applyConfig = React.useCallback((value: EgressRoutingConfig) => {
    setConfig({ ...value, rules: Array.isArray(value.rules) ? value.rules : [] });
    setThreshold(String(value.fallback.failure_threshold));
    setCooldown(String(value.fallback.cooldown_seconds));
    setDirty(false);
  }, []);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    try {
      if (!loaded) {
        const settings = await api.egressRouting();
        applyConfig(settings.config);
        setLoaded(true);
      }
      const [currentStatus, currentAudit] = await Promise.all([api.egressRoutingStatus(), api.egressRoutingAudit()]);
      setStatus(currentStatus.status);
      setStatusFetchedAt(Date.now());
      setEvents(currentAudit.events || []);
      setLoadError("");
    } catch (error) {
      toast.error(`读取出口状态失败：${(error as Error).message}`);
    } finally {
      setRefreshing(false);
    }
  }, [loaded, applyConfig]);

  React.useEffect(() => {
    let cancelled = false;
    Promise.allSettled([api.egressRouting(), api.egressRoutingStatus(), api.egressRoutingAudit()])
      .then(([settings, currentStatus, audit]) => {
        if (cancelled) return;
        const errors: string[] = [];
        if (settings.status === "fulfilled") {
          applyConfig(settings.value.config);
          setLoaded(true);
        } else {
          errors.push((settings.reason as Error).message);
        }
        if (currentStatus.status === "fulfilled") {
          setStatus(currentStatus.value.status);
          setStatusFetchedAt(Date.now());
        } else errors.push((currentStatus.reason as Error).message);
        if (audit.status === "fulfilled") setEvents(audit.value.events || []);
        else errors.push((audit.reason as Error).message);
        setLoadError(errors.join("；"));
      })
      .catch((error: Error) => {
        if (!cancelled) setLoadError(error.message);
      });
    return () => { cancelled = true; };
  }, [applyConfig]);

  function changeRule(id: string, change: Partial<EgressRoutingRule>) {
    setConfig((previous) => ({
      ...previous,
      rules: previous.rules.map((rule) => rule.id === id ? { ...rule, ...change } : rule),
    }));
    setDirty(true);
  }

  function addRule() {
    const suffix = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setConfig((previous) => ({
      ...previous,
      rules: [...previous.rules, { id: `rule-${suffix}`, type: "domain", value: "", provider: "clash", allow_fallback: false, enabled: true }],
    }));
    setDirty(true);
  }

  function moveRule(index: number, direction: number) {
    setConfig((previous) => {
      const rules = [...previous.rules];
      const destination = index + direction;
      if (destination < 0 || destination >= rules.length) return previous;
      [rules[index], rules[destination]] = [rules[destination], rules[index]];
      return { ...previous, rules };
    });
    setDirty(true);
  }

  async function save() {
    const failureThreshold = Number(threshold);
    const cooldownSeconds = Number(cooldown);
    if (!Number.isInteger(failureThreshold) || failureThreshold < 1 || failureThreshold > 100) {
      toast.error("连续失败阈值须为 1–100 的整数");
      return;
    }
    if (!Number.isInteger(cooldownSeconds) || cooldownSeconds < 1 || cooldownSeconds > 86400) {
      toast.error("冷却时间须为 1–86400 秒的整数");
      return;
    }
    if (config.rules.some((rule) => !rule.value.trim())) {
      toast.error("请填写每条规则的目标，或删除空规则");
      return;
    }
    setSaving(true);
    try {
      const saved = await api.saveEgressRouting({
        ...config,
        rules: config.rules.map((rule) => ({ ...rule, value: rule.value.trim(), allow_fallback: rule.provider === "tor" && rule.allow_fallback })),
        fallback: { ...config.fallback, failure_threshold: failureThreshold, cooldown_seconds: cooldownSeconds },
      });
      applyConfig(saved.config);
      toast.success("已保存出口规则，对之后的新请求生效");
      await refresh();
    } catch (error) {
      toast.error(`保存出口规则失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    if (!testURL.trim()) {
      toast.error("请填写检测地址");
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testEgressRouting({
        url: testURL.trim(), task_id: testTask.trim() || undefined,
        agent_key: testAgent.trim() || undefined, mode: testMode,
      });
      setTestResult(result);
      if (result.ok) toast.success("出口检测完成");
      else toast.error(result.error || result.probe?.error || "所选出口不可用");
      await refresh();
    } catch (error) {
      toast.error(`出口检测失败：${(error as Error).message}`);
    } finally {
      setTesting(false);
    }
  }

  const disabled = !loaded || saving;
  let clashStatus = "读取中";
  if (status) {
    clashStatus = status.clash.ready ? "就绪" : "不可用";
    if (!status.clash.enabled) clashStatus = "未启用";
  }
  const placeholders: Record<EgressRuleType, string> = {
    domain: "example.com", suffix: "example.com", ip: "203.0.113.10", cidr: "203.0.113.0/24",
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><RouteIcon className="size-4" />Tor 主出口与 Clash 备用</CardTitle>
        <CardDescription>
          默认目标流量使用 Tor。任务显式选择优先于 Agent，Agent 优先于以下目标规则；规则从上到下匹配。
          现有平台白名单保留，代理不可用时拒绝连接。
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {loadError && <p role="alert" className="text-destructive text-xs">读取出口信息失败：{loadError}</p>}
        <div className="flex flex-wrap items-center gap-2 text-xs" aria-live="polite">
          <Badge variant={status?.tor.ready ? "default" : "secondary"}>
            Tor {status ? `${status.tor.ready ? "就绪" : "未就绪"} · ${status.tor.running}/${status.tor.size}` : "读取中"}
          </Badge>
          <Badge variant={status?.clash.ready ? "default" : "secondary"}>
            Clash {clashStatus}
          </Badge>
          {status && <span className="text-muted-foreground">代理节点 {status.clash.node_count || 0} · 当前节点 {status.clash.selected || "—"}</span>}
          <Button type="button" size="sm" variant="ghost" onClick={refresh} disabled={refreshing}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} />刷新状态
          </Button>
        </div>
        {status?.clash.error && <p className="text-destructive text-xs">Clash：{status.clash.error}</p>}

        <div className="grid gap-3">
          <div className="flex items-center justify-between gap-2">
            <Label className="text-sm">目标规则</Label>
            <Button type="button" size="sm" variant="outline" onClick={addRule} disabled={disabled}><PlusIcon />添加规则</Button>
          </div>
          {config.rules.length === 0 && <p className="text-muted-foreground text-xs">尚无目标规则，继承系统策略的目标请求默认使用 Tor。</p>}
          {config.rules.map((rule, index) => (
            <div key={rule.id} className="grid gap-3 rounded-md border p-3">
              <div className="flex items-center justify-between gap-2">
                <label className="flex items-center gap-2 text-xs" htmlFor={`route-enabled-${rule.id}`}>
                  <Switch id={`route-enabled-${rule.id}`} checked={rule.enabled} disabled={disabled}
                    onCheckedChange={(enabled) => changeRule(rule.id, { enabled })} />
                  规则 {index + 1}
                </label>
                <div className="flex gap-1">
                  <Button type="button" size="icon-sm" variant="ghost" aria-label={`上移规则 ${index + 1}`} disabled={disabled || index === 0} onClick={() => moveRule(index, -1)}><ArrowUpIcon /></Button>
                  <Button type="button" size="icon-sm" variant="ghost" aria-label={`下移规则 ${index + 1}`} disabled={disabled || index === config.rules.length - 1} onClick={() => moveRule(index, 1)}><ArrowDownIcon /></Button>
                  <Button type="button" size="icon-sm" variant="ghost" aria-label={`删除规则 ${index + 1}`} disabled={disabled} onClick={() => {
                    setConfig((previous) => ({ ...previous, rules: previous.rules.filter((item) => item.id !== rule.id) }));
                    setDirty(true);
                  }}><Trash2Icon /></Button>
                </div>
              </div>
              <div className="flex flex-wrap items-end gap-2">
                <div className="grid gap-1">
                  <Label htmlFor={`route-type-${rule.id}`} className="text-xs">匹配方式</Label>
                  <NativeSelect id={`route-type-${rule.id}`} value={rule.type} disabled={disabled} onChange={(event) => changeRule(rule.id, { type: event.target.value as EgressRuleType })}>
                    <NativeSelectOption value="domain">完整域名</NativeSelectOption>
                    <NativeSelectOption value="suffix">域名及子域</NativeSelectOption>
                    <NativeSelectOption value="ip">指定 IP</NativeSelectOption>
                    <NativeSelectOption value="cidr">IP 网段</NativeSelectOption>
                  </NativeSelect>
                </div>
                <div className="grid min-w-36 flex-1 gap-1">
                  <Label htmlFor={`route-value-${rule.id}`} className="text-xs">目标</Label>
                  <Input id={`route-value-${rule.id}`} className="h-8 font-mono text-xs" value={rule.value} disabled={disabled}
                    placeholder={placeholders[rule.type]}
                    onChange={(event) => changeRule(rule.id, { value: event.target.value })} />
                </div>
                <div className="grid gap-1">
                  <Label htmlFor={`route-provider-${rule.id}`} className="text-xs">出口</Label>
                  <NativeSelect id={`route-provider-${rule.id}`} value={rule.provider} disabled={disabled} onChange={(event) => {
                    const provider = event.target.value as EgressProvider;
                    changeRule(rule.id, { provider, allow_fallback: provider === "tor" && rule.allow_fallback });
                  }}>
                    <NativeSelectOption value="tor">Tor</NativeSelectOption>
                    <NativeSelectOption value="clash">Clash</NativeSelectOption>
                  </NativeSelect>
                </div>
              </div>
              {rule.provider === "tor" && (
                <label className="flex items-center gap-2 text-xs" htmlFor={`route-fallback-${rule.id}`}>
                  <Switch id={`route-fallback-${rule.id}`} checked={rule.allow_fallback} disabled={disabled}
                    onCheckedChange={(allow_fallback) => changeRule(rule.id, { allow_fallback })} />
                  此目标允许 Tor 失败后使用 Clash
                </label>
              )}
            </div>
          ))}
          <p className="text-muted-foreground text-xs">IP 规则只匹配请求中明确使用的 IP，不为分流额外执行本地 DNS 查询。</p>
        </div>

        <Separator />
        <div className="grid gap-3">
          <div className="flex items-center justify-between gap-3">
            <div className="grid gap-1">
              <Label htmlFor="routing-fallback">自动备用</Label>
              <p className="text-muted-foreground text-xs">仅对已允许备用的 Tor 规则生效；明确指定 Tor 的任务或 Agent 不自动切换。</p>
            </div>
            <Switch id="routing-fallback" checked={config.fallback.enabled} disabled={disabled} onCheckedChange={(enabled) => {
              setConfig((previous) => ({ ...previous, fallback: { ...previous.fallback, enabled } }));
              setDirty(true);
            }} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="routing-threshold" className="text-xs">连续失败阈值</Label>
              <Input id="routing-threshold" type="number" min={1} max={100} value={threshold} disabled={disabled}
                onChange={(event) => { setThreshold(event.target.value); setDirty(true); }} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="routing-cooldown" className="text-xs">Clash 冷却时间（秒）</Label>
              <Input id="routing-cooldown" type="number" min={1} max={86400} value={cooldown} disabled={disabled}
                onChange={(event) => { setCooldown(event.target.value); setDirty(true); }} />
            </div>
          </div>
          <p className="text-muted-foreground text-xs">冷却结束后，新请求重新尝试 Tor。POST 等有副作用的请求不会自动重放；两个出口均失败时拒绝连接。</p>
          {status && (status.fallback_states || []).length > 0 && (
            <div className="max-h-36 overflow-auto rounded-md border p-2 text-xs">
              {(status.fallback_states || []).map((state) => (
                <div key={`${state.task_id}-${state.agent_key}-${state.host}`} className="flex flex-wrap gap-x-3 gap-y-1 py-1">
                  <span className="break-all font-mono">{state.host || "—"}</span>
                  <span>连续失败 {state.failures || 0} 次</span>
                  {state.fallback_until && new Date(state.fallback_until).getTime() > statusFetchedAt
                    ? <span>Clash 备用至 {timestamp(state.fallback_until)}</span>
                    : <span className="text-muted-foreground">下次请求尝试 Tor</span>}
                </div>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <Button type="button" onClick={save} disabled={disabled || !dirty}>{saving ? "保存中…" : "保存出口规则"}</Button>
            {dirty && <span className="text-muted-foreground text-xs">有尚未保存的修改</span>}
          </div>
        </div>

        <Separator />
        <div className="grid gap-3">
          <Label className="text-sm">出口实测</Label>
          <p className="text-muted-foreground text-xs">使用已保存的规则检测实际出口。填写任务和 Agent 可核验对应的选择优先级。</p>
          <div className="flex flex-wrap gap-2">
            <NativeSelect aria-label="检测出口" value={testMode} disabled={!loaded || testing} onChange={(event) => setTestMode(event.target.value as typeof testMode)}>
              <NativeSelectOption value="inherit">按任务与规则选择</NativeSelectOption>
              <NativeSelectOption value="tor">指定 Tor</NativeSelectOption>
              <NativeSelectOption value="clash">指定 Clash</NativeSelectOption>
            </NativeSelect>
            <Input aria-label="检测任务 ID（可选）" className="h-8 w-32 text-xs" placeholder="任务 ID（可选）" value={testTask} disabled={!loaded || testing} onChange={(event) => setTestTask(event.target.value)} />
            <Input aria-label="检测 Agent" className="h-8 w-32 text-xs" placeholder="Agent" value={testAgent} disabled={!loaded || testing} onChange={(event) => setTestAgent(event.target.value)} />
          </div>
          <div className="flex gap-2">
            <Input aria-label="出口检测地址" className="h-8 min-w-0 flex-1 font-mono text-xs" value={testURL} disabled={!loaded || testing} onChange={(event) => setTestURL(event.target.value)} />
            <Button type="button" size="sm" variant="outline" onClick={test} disabled={!loaded || testing}>{testing ? "检测中…" : "检测出口"}</Button>
          </div>
          {testResult && (
            <div className="grid gap-1 rounded-md bg-muted/40 p-3 text-xs" role="status">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={testResult.ok ? "default" : "destructive"}>{testResult.ok ? "请求成功" : "请求被拒绝或失败"}</Badge>
                <span>出口：{providerName(testResult.resolved?.provider)}</span>
                {testResult.probe?.ip && <span className="font-mono">{testResult.probe.ip}</span>}
                {testResult.probe?.ip && <span>{testResult.probe.is_tor ? "实测 Tor 出口" : "实测非 Tor 出口"}</span>}
              </div>
              {testResult.resolved?.rule_id && <span>命中规则：{testResult.resolved.rule_id}</span>}
              {testResult.resolved?.reason && <span>{reasonName(testResult.resolved.reason)}</span>}
              {(testResult.error || testResult.probe?.error) && <span className="text-destructive">{testResult.error || testResult.probe?.error}</span>}
            </div>
          )}
        </div>

        <Separator />
        <div className="grid gap-2">
          <Label className="text-sm">最近出口审计</Label>
          {events.length === 0 ? <p className="text-muted-foreground text-xs">尚无请求记录。发起出口检测或运行任务后刷新查看。</p> : (
            <div className="max-h-80 overflow-auto rounded-md border">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-muted"><tr><th className="p-2">时间 / 目标</th><th className="p-2">出口 / IP</th><th className="p-2">规则 / 原因</th></tr></thead>
                <tbody>{events.slice(0, 100).map((event) => (
                  <tr key={`${event.timestamp}-${event.task_id}-${event.agent_key}-${event.host}-${event.provider}-${event.reason}`} className="border-t align-top">
                    <td className="p-2"><div className="whitespace-nowrap">{timestamp(event.timestamp)}</div><div className="break-all font-mono">{event.host}</div><div className="text-muted-foreground">{event.task_id ? `任务 ${event.task_id}` : "无任务"}{event.agent_key ? ` · ${event.agent_key}` : ""}</div></td>
                    <td className="p-2"><div>{providerName(event.provider)}</div><div className="font-mono">{event.exit_ip || "未实测"}</div>{event.exit_ip_source === "same-provider-probe" && <div className="text-muted-foreground">独立出口检测</div>}{event.is_tor != null && <div>{event.is_tor ? "Tor 出口" : "非 Tor 出口"}</div>}</td>
                    <td className="p-2"><div className="break-all">{event.rule_id || "默认 / 显式选择"}</div><div>{reasonName(event.reason)}</div>{event.error && <div className="text-destructive">{event.error}</div>}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
