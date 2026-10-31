#!/bin/sh
# 宿主机定时任务：模型端点的 IP 会漂移，而容器内 DNS 已全部走 Tor、且直连白名单按 IP
# 生效。这里用宿主机（直连）重新解析，刷新容器 /etc/hosts 与 iptables 直连规则。
#
# 用法: ./refresh-llm-direct.sh [容器名] [域名...]
#   ./refresh-llm-direct.sh artex1-artex-1 api.deepseek.com
set -u
CONTAINER="${1:-artex1-artex-1}"
shift 2>/dev/null || true
HOSTS="${*:-api.deepseek.com}"

for h in $HOSTS; do
  ips=$(getent ahostsv4 "$h" | awk '{print $1}' | sort -u | tr '\n' ' ')
  [ -n "${ips% }" ] || { echo "[refresh] $h 解析失败，跳过" >&2; continue; }
  echo "[refresh] $h -> $ips"
  docker exec "$CONTAINER" sh -c '
    h="$1"; shift
    tmp=/tmp/hosts.refresh
    grep -v "[[:space:]]$h\$" /etc/hosts > "$tmp" || true
    for ip in "$@"; do printf "%s\t%s\n" "$ip" "$h" >> "$tmp"; done
    cat "$tmp" > /etc/hosts
  ' sh "$h" $ips || continue
  docker exec -e ARTEX_DIRECT_IPS="$ips" "$CONTAINER" \
    /usr/local/bin/artex-entry.sh --refresh-rules >/dev/null 2>&1 \
    && echo "[refresh] $h 直连规则已同步"
done
