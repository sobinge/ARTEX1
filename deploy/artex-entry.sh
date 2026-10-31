#!/bin/sh
# 容器入口：把容器内**全部**出站流量强制进 Tor（透明代理）。
#   - TCP  : nat OUTPUT REDIRECT -> 127.0.0.1:9040  (tor TransPort)
#   - DNS  : udp/tcp 53            -> 127.0.0.1:19053 (tor DNSPort)
#   - 其它 : UDP/ICMP 直接丢弃（Tor 不承载 UDP，宁可失败也不真实出网）
# 放行：tor 自身（独立 uid artestor）、loopback、容器内网、已建立连接（含本容器
#       对外提供服务的回包）。
# 需要 NET_ADMIN。排障可用 ARTEX_TRANSPARENT_TOR=0 关闭。
set -u

TOR_UID="$(id -u artestor 2>/dev/null || echo '')"

install_rules() {
  command -v iptables >/dev/null 2>&1 || return 1

  iptables -t nat -N ARTEX_TP 2>/dev/null || true
  iptables -t nat -F ARTEX_TP || return 1
  # DNS 必须先匹配：否则会被下面的 loopback RETURN 放行回系统解析器
  iptables -t nat -A ARTEX_TP -p udp --dport 53 -j REDIRECT --to-ports 19053 || return 1
  iptables -t nat -A ARTEX_TP -p tcp --dport 53 -j REDIRECT --to-ports 19053 || return 1
  iptables -t nat -A ARTEX_TP -o lo -j RETURN || return 1
  iptables -t nat -A ARTEX_TP -d 127.0.0.0/8 -j RETURN || return 1
  iptables -t nat -A ARTEX_TP -d 172.16.0.0/12 -j RETURN || return 1
  iptables -t nat -A ARTEX_TP -d 10.0.0.0/8 -j RETURN || return 1
  iptables -t nat -A ARTEX_TP -d 192.168.0.0/16 -j RETURN || return 1
  if [ -n "$TOR_UID" ]; then
    iptables -t nat -A ARTEX_TP -m owner --uid-owner "$TOR_UID" -j RETURN || return 1
  fi
  iptables -t nat -A ARTEX_TP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
  iptables -t nat -A ARTEX_TP -p tcp -j REDIRECT --to-ports 9040 || return 1
  iptables -t nat -C OUTPUT -j ARTEX_TP 2>/dev/null || iptables -t nat -A OUTPUT -j ARTEX_TP || return 1

  iptables -N ARTEX_DROP 2>/dev/null || true
  iptables -F ARTEX_DROP || return 1
  iptables -A ARTEX_DROP -o lo -j RETURN || return 1
  iptables -A ARTEX_DROP -d 127.0.0.0/8 -j RETURN || return 1
  iptables -A ARTEX_DROP -d 172.16.0.0/12 -j RETURN || return 1
  iptables -A ARTEX_DROP -d 10.0.0.0/8 -j RETURN || return 1
  iptables -A ARTEX_DROP -d 192.168.0.0/16 -j RETURN || return 1
  if [ -n "$TOR_UID" ]; then
    iptables -A ARTEX_DROP -m owner --uid-owner "$TOR_UID" -j RETURN || return 1
  fi
  iptables -A ARTEX_DROP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
  iptables -A ARTEX_DROP -p tcp -j RETURN || return 1
  iptables -A ARTEX_DROP -p udp -j DROP || return 1
  iptables -A ARTEX_DROP -p icmp -j DROP || return 1
  iptables -C OUTPUT -j ARTEX_DROP 2>/dev/null || iptables -A OUTPUT -j ARTEX_DROP || return 1
  return 0
}

# 直连白名单：大模型/平台自身走真实出口（Tor 出口常被模型厂商封，且 Tor DNS 对
# 部分域名会 SERVFAIL）。域名由 compose 的 extra_hosts 固定，这里只放行目标 IP。
apply_direct_ips() {
  for ip in ${ARTEX_DIRECT_IPS:-}; do
    iptables -t nat -I ARTEX_TP 1 -d "$ip" -j RETURN 2>/dev/null || return 1
    iptables -I ARTEX_DROP 1 -d "$ip" -j RETURN 2>/dev/null || return 1
    echo "[entry] 直连白名单: $ip"
  done
  return 0
}

# 供宿主机定时刷新直连白名单时复用（只重装规则，不启动应用）
if [ "${1:-}" = "--refresh-rules" ]; then
  if install_rules; then
    apply_direct_ips
    exit 0
  fi
  exit 1
fi

if [ "${ARTEX_TRANSPARENT_TOR:-1}" = "0" ]; then
  echo "[entry] ARTEX_TRANSPARENT_TOR=0，跳过透明代理规则" >&2
elif install_rules; then
  echo "[entry] 全流量透明代理已启用: TCP->TransPort 9040, DNS->DNSPort 19053, UDP/ICMP 丢弃"
  apply_direct_ips || echo "[entry] 警告: 直连白名单规则安装失败" >&2
else
  echo "[entry] 警告: 透明代理规则安装失败（缺 NET_ADMIN/iptables）" >&2
fi

exec /app/start.sh "$@"
