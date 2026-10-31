#!/bin/sh
# 容器内：以 clash 用户重启 mihomo（单实例）。
# 注意：镜像里没有 procps（无 pgrep/pkill），只能扫描 /proc 取 PID。
# clash uid 在 iptables 中有出站豁免，因此 Clash 的上游连接不会被容器的 Tor 代理劫持。
set -u
CFG=/app/data/clash/config.yaml
DIR=/app/data/clash
BIN=/usr/local/bin/mihomo

[ -x "$BIN" ] || { echo "[clash] 未安装 mihomo" >&2; exit 1; }
[ -f "$CFG" ] || { echo "[clash] 缺少配置 $CFG" >&2; exit 1; }

mkdir -p "$DIR"
chown -R clash:clash "$DIR" 2>/dev/null || true

# 杀掉所有已有 mihomo
for p in /proc/[0-9]*; do
  [ "$(cat "$p/comm" 2>/dev/null)" = "mihomo" ] && kill "${p#/proc/}" 2>/dev/null
done
i=0
while [ "$i" -lt 20 ]; do
  alive=0
  for p in /proc/[0-9]*; do
    [ "$(cat "$p/comm" 2>/dev/null)" = "mihomo" ] && alive=1
  done
  [ "$alive" = "0" ] && break
  i=$((i+1)); sleep 0.3
done

setpriv --reuid clash --regid clash --init-groups "$BIN" -d "$DIR" -f "$CFG" >>"$DIR/mihomo.log" 2>&1 &

i=0
while [ "$i" -lt 20 ]; do
  sleep 0.5
  if curl -s --max-time 2 http://127.0.0.1:9090/version >/dev/null 2>&1; then
    n=0
    for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "mihomo" ] && n=$((n+1)); done
    echo "[clash] 已启动（实例数=$n）: mixed-port 127.0.0.1:7890, controller 127.0.0.1:9090"
    exit 0
  fi
  i=$((i+1))
done
echo "[clash] 启动失败，最近日志:" >&2
tail -5 "$DIR/mihomo.log" >&2 2>/dev/null || true
exit 1
