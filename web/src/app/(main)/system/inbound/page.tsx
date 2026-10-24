"use client";

import * as React from "react";

import { toast } from "sonner";
import { KeyRoundIcon, PlusIcon, RefreshCwIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "@/lib/api";

type OnionService = { name: string; onion: string; clients: string[]; clients_n: number };

// Inbound channels page: self-hosted Tor hidden services with mandatory client
// authorization. Bare onion services are refused by the backend, so a service
// with zero clients cannot be enabled.
export default function InboundPage() {
  const [services, setServices] = React.useState<OnionService[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [newName, setNewName] = React.useState("");
  const [newTarget, setNewTarget] = React.useState("127.0.0.1:8787");
  const [torrc, setTorrc] = React.useState<string | null>(null);
  const [clientFor, setClientFor] = React.useState<string | null>(null);
  const [clientName, setClientName] = React.useState("");
  const [secret, setSecret] = React.useState<{ client: string; auth_private: string; fingerprint: string } | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .inboundOnionServices()
      .then((r) => setServices(r.services ?? []))
      .catch((e) => toast.error(`加载失败：${(e as Error).message}`))
      .finally(() => setLoading(false));
  }, []);
  React.useEffect(load, [load]);

  async function createService() {
    try {
      const r = await api.createInboundOnion({ name: newName, target: newTarget });
      setTorrc(r.torrc);
      setNewName("");
      toast.success("已创建服务目录。请把 torrc 片段加入 Tor 配置并重启。");
      load();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    }
  }

  async function addClient() {
    if (!clientFor) return;
    try {
      const r = await api.addInboundOnionClient(clientFor, clientName);
      setSecret({ client: r.client, auth_private: r.auth_private, fingerprint: r.fingerprint });
      setClientName("");
      setClientFor(null);
      load();
      if (!r.applied) toast.warning("已写入授权，但未能自动重载 Tor，请手动重启或 SIGHUP。");
    } catch (e) {
      toast.error(`授权失败：${(e as Error).message}`);
    }
  }

  async function revoke(name: string, client: string) {
    try {
      await api.revokeInboundOnionClient(name, client);
      toast.success("已吊销该客户端授权");
      load();
    } catch (e) {
      toast.error(`吊销失败：${(e as Error).message}`);
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">入站通道</h1>
        <p className="text-muted-foreground text-sm">
          自建 Onion Service，强制客户端授权。目标侧只能看到 <code>.onion</code> 地址，平台真实 IP 不暴露。
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <PlusIcon className="size-4" />
            新建 Onion Service
          </CardTitle>
          <CardDescription>
            服务目录建在 <code>data/inbound/onion/&lt;name&gt;</code>。被映射的端口必须只监听回环，
            否则目标仍可按 IP 直连，隐藏服务就失去意义。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="svc-name" className="text-xs">服务名</Label>
            <Input id="svc-name" className="h-8 w-48" placeholder="c2-prod" value={newName}
              onChange={(e) => setNewName(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="svc-target" className="text-xs">映射目标（仅回环）</Label>
            <Input id="svc-target" className="h-8 w-56 font-mono text-xs" value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)} />
          </div>
          <Button size="sm" onClick={createService} disabled={!newName.trim()}>
            创建
          </Button>
        </CardContent>
      </Card>

      {torrc && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">torrc 片段</CardTitle>
            <CardDescription>加入 Tor 配置后重启（或 SIGHUP），<code>hostname</code> 文件出现后即可授权客户端。</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">{torrc}</pre>
          </CardContent>
        </Card>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium">已管理的服务</h2>
        <Button size="sm" variant="ghost" onClick={load} disabled={loading}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>

      {services.length === 0 ? (
        <p className="text-muted-foreground text-sm">还没有服务。先创建一个，再把 torrc 片段加进 Tor。</p>
      ) : (
        services.map((s) => (
          <Card key={s.name}>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                <ShieldCheckIcon className="size-4" />
                {s.name}
                <Badge variant={s.onion ? "default" : "secondary"}>{s.onion ? "已上线" : "待启动"}</Badge>
                <Badge variant={s.clients_n > 0 ? "outline" : "destructive"}>
                  {s.clients_n > 0 ? `${s.clients_n} 个授权客户端` : "无客户端 · 拒绝启用"}
                </Badge>
              </CardTitle>
              <CardDescription className="font-mono text-xs">{s.onion || "尚未生成 onion 地址"}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => setClientFor(s.name)}>
                  <KeyRoundIcon className="size-4" /> 授权客户端
                </Button>
                <Button size="sm" variant="outline"
                  onClick={() => api.enableOnionService(s.name)
                    .then(() => toast.success("校验通过：至少有一个授权客户端"))
                    .catch((e) => toast.error(`拒绝启用：${(e as Error).message}`))}>
                  校验可启用
                </Button>
              </div>
              {s.clients.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {s.clients.map((c) => (
                    <span key={c} className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs">
                      <span className="font-mono">{c}</span>
                      <Button size="icon-sm" variant="ghost" onClick={() => revoke(s.name, c)}>
                        <Trash2Icon className="size-3" />
                      </Button>
                    </span>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        ))
      )}

      <Dialog open={!!clientFor} onOpenChange={(o) => !o && setClientFor(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>授权客户端</DialogTitle>
            <DialogDescription>
              平台生成 X25519 密钥对，只把私钥交付一次，不落库。客户端需把它写入
              <code> ClientOnionAuthDir/&lt;name&gt;.auth_private</code>。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="client-name" className="text-xs">客户端名</Label>
            <Input id="client-name" className="h-8" placeholder="agent-01" value={clientName}
              onChange={(e) => setClientName(e.target.value)} />
            <Button size="sm" onClick={addClient} disabled={!clientName.trim()}>生成并授权</Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!secret} onOpenChange={(o) => !o && setSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>客户端密钥（只显示一次）</DialogTitle>
            <DialogDescription>
              把这个文件内容交付给目标侧：<code>{secret?.client}.auth_private</code>。关闭后平台无法再显示。
            </DialogDescription>
          </DialogHeader>
          <pre className="max-h-48 overflow-auto rounded-md bg-muted p-3 text-xs whitespace-pre-wrap">
            {secret?.auth_private}
          </pre>
          <p className="text-muted-foreground text-xs">公钥指纹：{secret?.fingerprint}</p>
        </DialogContent>
      </Dialog>
    </div>
  );
}
