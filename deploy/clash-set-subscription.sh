#!/bin/sh
# 宿主机执行：拉取 Clash 订阅并下发到容器（本地入站强制只绑 127.0.0.1）。
# 用法: ./clash-set-subscription.sh <订阅URL> [容器名]
set -eu
URL="${1:?用法: $0 <clash 订阅URL> [容器名]}"
CONTAINER="${2:-artex1-artex-1}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/data/clash"
mkdir -p "$DIR"
chmod 700 "$DIR" 2>/dev/null || true

# 宿主机直连下载：容器内的下载会经过 Tor，订阅站通常封 Tor 出口
tmp="$DIR/.sub.$$"
curl -fsSL --max-time 60 -A "clash-verge/v1.7" -o "$tmp" "$URL"

if ! grep -qE '^[[:space:]]*(proxies|proxy-groups)[[:space:]]*:' "$tmp"; then
  echo "[clash] 订阅内容不是 Clash YAML（可能是 base64 的 v2ray 链接列表），需要先转换" >&2
  rm -f "$tmp"; exit 2
fi

python3 - "$tmp" > "$tmp.out" <<'PY'
import re, sys
src = sys.argv[1]
out = []
for line in open(src, encoding="utf-8", errors="replace"):
    # 订阅里的入站/控制器配置一律丢弃，避免暴露到 0.0.0.0
    if re.match(r'^(mixed-port|port|socks-port|redir-port|tproxy-port|external-controller|bind-address|allow-lan)\s*:', line):
        continue
    out.append(line)
sys.stdout.write(
    "# 由 clash-set-subscription.sh 生成；入站只绑回环\n"
    "mixed-port: 7890\nallow-lan: false\nbind-address: 127.0.0.1\n"
    "external-controller: 127.0.0.1:9090\n" + "".join(out)
)
PY
mv "$tmp.out" "$DIR/config.yaml"
chmod 600 "$DIR/config.yaml"
rm -f "$tmp"
# 容器内 clash uid 固定 912
chown 912:912 "$DIR/config.yaml" 2>/dev/null || true
docker exec "$CONTAINER" /usr/local/bin/artex-clash-restart.sh
