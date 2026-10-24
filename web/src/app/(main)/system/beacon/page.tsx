"use client";

import * as React from "react";

import { toast } from "sonner";
import { DownloadIcon, PlusIcon, RadioTowerIcon, RefreshCwIcon, SendIcon, ShieldOffIcon, UploadIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";

type Channel = Awaited<ReturnType<typeof api.beaconChannels>>["channels"][number];

// Beacon channels: a dead-drop model where neither peer listens on a port.
// The operator poll endpoint refuses to run without an anonymous egress, so the
// mailbox provider never learns the platform's IP.
export default function BeaconPage() {
  const [channels, setChannels] = React.useState<Channel[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [agentKey, setAgentKey] = React.useState("");
  const [taskID, setTaskID] = React.useState("");
  const [kind, setKind] = React.useState("onion");
  const [endpoint, setEndpoint] = React.useState("");
  const [created, setCreated] = React.useState<{ channel_id: string; psk: string } | null>(null);
  const [cmdFor, setCmdFor] = React.useState<string | null>(null);
  const [payload, setPayload] = React.useState("");
  const [pulled, setPulled] = React.useState<{ seq: number; payload: string }[] | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .beaconChannels()
      .then((r) => setChannels(r.channels ?? []))
      .catch((e) => toast.error(`加载失败：${(e as Error).message}`))
      .finally(() => setLoading(false));
  }, []);
  React.useEffect(load, [load]);

  async function create() {
    try {
      const r = await api.createBeaconChannel({ agent_key: agentKey, task_id: taskID, kind, endpoint });
      setCreated({ channel_id: r.channel_id, psk: r.psk });
      setAgentKey("");
      setEndpoint("");
      load();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    }
  }

  async function send() {
    if (!cmdFor) return;
    try {
      const r = await api.enqueueBeaconCommand(cmdFor, payload);
      toast.success(`已入队（seq ${r.seq}）`);
      setPayload("");
      setCmdFor(null);
    } catch (e) {
      toast.error(`入队失败：${(e as Error).message}`);
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">信标通道</h1>
        <p className="text-muted-foreground text-sm">
          信箱模型（dead drop）：目标与操作端都只做出站连接，任何一方都不监听端口。
          载荷端到端加密、定长填充，操作端轮询强制经匿名出口。
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <PlusIcon className="size-4" />
            新建信道
          </CardTitle>
          <CardDescription>
            endpoint 是目标侧看到的地址（onion 地址或 CDN 前置域名），不得指向平台自身地址。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="b-agent" className="text-xs">Agent</Label>
            <Input id="b-agent" className="h-8 w-40" placeholder="pentest" value={agentKey}
              onChange={(e) => setAgentKey(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="b-task" className="text-xs">任务 ID（可选）</Label>
            <Input id="b-task" className="h-8 w-32" value={taskID}
              onChange={(e) => setTaskID(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label className="text-xs">信箱类型</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="onion">Onion Service</SelectItem>
                <SelectItem value="cdn_front">CDN 前置域名</SelectItem>
                <SelectItem value="third_party">第三方通道</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="b-endpoint" className="text-xs">目标侧地址</Label>
            <Input id="b-endpoint" className="h-8 w-72 font-mono text-xs" placeholder="xxxxxxxx.onion 或 https://cdn.example.com/drop"
              value={endpoint} onChange={(e) => setEndpoint(e.target.value)} />
          </div>
          <Button size="sm" onClick={create} disabled={!agentKey.trim() || !endpoint.trim()}>
            创建
          </Button>
        </CardContent>
      </Card>

      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium">信道列表</h2>
        <Button size="sm" variant="ghost" onClick={load} disabled={loading}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>

      {channels.length === 0 ? (
        <p className="text-muted-foreground text-sm">还没有信道。</p>
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <table className="w-full text-xs">
            <thead className="bg-muted/50 text-left">
              <tr>
                <th className="p-2">信道</th>
                <th className="p-2">Agent</th>
                <th className="p-2">类型</th>
                <th className="p-2">目标侧地址</th>
                <th className="p-2">最近心跳</th>
                <th className="p-2">状态</th>
                <th className="p-2"></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.channel_id} className="border-t">
                  <td className="p-2 font-mono">{c.channel_id.slice(0, 12)}…</td>
                  <td className="p-2">{c.agent_key}</td>
                  <td className="p-2">{c.kind}</td>
                  <td className="max-w-[22rem] truncate p-2 font-mono">{c.endpoint}</td>
                  <td className="p-2">{c.silent_secs != null ? `${c.silent_secs}s 前` : "从未"}</td>
                  <td className="p-2">
                    {c.revoked_at ? <Badge variant="destructive">已吊销</Badge> : <Badge variant="outline">活跃</Badge>}
                  </td>
                  <td className="p-2">
                    <div className="flex items-center gap-1">
                      <Button size="icon-sm" variant="ghost" title="下发指令" disabled={!!c.revoked_at}
                        onClick={() => setCmdFor(c.channel_id)}>
                        <SendIcon className="size-3" />
                      </Button>
                      <Button size="icon-sm" variant="ghost" title="推送到信箱" disabled={!!c.revoked_at}
                        onClick={() => api.flushBeaconOutbox(c.channel_id)
                          .then((r) => toast.success(`已推送 ${r.sent} 条`))
                          .catch((e) => toast.error(`推送失败：${(e as Error).message}`))}>
                        <UploadIcon className="size-3" />
                      </Button>
                      <Button size="icon-sm" variant="ghost" title="从信箱拉取结果" disabled={!!c.revoked_at}
                        onClick={() => api.pullBeaconInbox(c.channel_id)
                          .then((r) => { setPulled(r.messages ?? []); load(); })
                          .catch((e) => toast.error(`拉取失败：${(e as Error).message}`))}>
                        <DownloadIcon className="size-3" />
                      </Button>
                      <Button size="icon-sm" variant="ghost" title="吊销" disabled={!!c.revoked_at}
                        onClick={() => api.revokeBeaconChannel(c.channel_id)
                          .then(() => { toast.success("已吊销"); load(); })
                          .catch((e) => toast.error(`吊销失败：${(e as Error).message}`))}>
                        <ShieldOffIcon className="size-3" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={!!created} onOpenChange={(o) => !o && setCreated(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>信道已创建（PSK 只显示一次）</DialogTitle>
            <DialogDescription>把 channel_id 与 PSK 同时交付给目标侧信标。</DialogDescription>
          </DialogHeader>
          <dl className="grid gap-2 text-xs">
            <div>
              <dt className="text-muted-foreground">channel_id</dt>
              <dd className="font-mono break-all">{created?.channel_id}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">psk（hex）</dt>
              <dd className="font-mono break-all">{created?.psk}</dd>
            </div>
          </dl>
        </DialogContent>
      </Dialog>

      <Dialog open={pulled !== null} onOpenChange={(o) => !o && setPulled(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>拉取到的信标结果</DialogTitle>
            <DialogDescription>
              已在平台侧用信道 PSK 解密，并从信箱删除对应帧。
            </DialogDescription>
          </DialogHeader>
          {pulled && pulled.length === 0 ? (
            <p className="text-muted-foreground text-sm">没有新消息。</p>
          ) : (
            <div className="grid max-h-72 gap-2 overflow-auto">
              {pulled?.map((m) => (
                <div key={m.seq} className="rounded-md border p-2 text-xs">
                  <div className="text-muted-foreground mb-1">seq {m.seq}</div>
                  <pre className="whitespace-pre-wrap break-all">{m.payload}</pre>
                </div>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={!!cmdFor} onOpenChange={(o) => !o && setCmdFor(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <RadioTowerIcon className="size-4" /> 下发指令
            </DialogTitle>
            <DialogDescription>
              指令会被加密并定长填充后写入信箱，目标侧下一个心跳周期取走。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="cmd" className="text-xs">指令内容</Label>
            <Input id="cmd" className="h-8 font-mono text-xs" placeholder="whoami" value={payload}
              onChange={(e) => setPayload(e.target.value)} />
            <Button size="sm" onClick={send} disabled={!payload.trim()}>入队</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
