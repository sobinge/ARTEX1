#!/bin/sh
# 容器内：以 clash 用户重启 mihomo。clash uid 在 iptables 中有出站豁免，
# 因此 Clash 的上游连接不会被容器的 Tor 透明代理劫持（Tor 被封时仍可用于测试）。
set -u
CFG=/app/data/clash/config.yaml
DIR=/app/data/clash
BIN=/usr/local/bin/mihomo

[ -x "$BIN" ] || { echo "[clash] 未安装 mihomo" >&2; exit 1; }
[ -f "$CFG" ] || { echo "[clash] 缺少配置 $CFG" >&2; exit 1; }

mkdir -p "$DIR"
chown -R clash:clash "$DIR" 2>/dev/null || true

pkill -f '^/usr/local/bin/mihomo' 2>/dev/null || true
sleep 1
setpriv --reuid clash --regid clash --init-groups "$BIN" -d "$DIR" -f "$CFG" >>"$DIR/mihomo.log" 2>&1 &
sleep 2
if curl -s --max-time 3 http://127.0.0.1:9090/version >/dev/null 2>&1; then
  echo "[clash] 已启动: mixed-port 127.0.0.1:7890, controller 127.0.0.1:9090"
else
  echo "[clash] 启动失败，最近日志:" >&2
  tail -5 "$DIR/mihomo.log" >&2 2>/dev/null || true
  exit 1
fi
