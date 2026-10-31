#!/bin/sh
# 容器入口：先把容器内**所有** DNS（含工具自己指定的 8.8.8.8 / 1.1.1.1 / --dns-servers，
# 以及忽略 /etc/resolv.conf 的实现）在 netfilter 层重定向到 Tor 的 DNSPort，
# 再启动应用。需要 NET_ADMIN；规则装不上只告警，不阻止启动。
set -u

install_dns_redirect() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -t nat -N ARTEX_DNS 2>/dev/null || true
  iptables -t nat -F ARTEX_DNS 2>/dev/null || return 1
  # 指向 Tor DNSPort 自身的流量不能再次重定向，否则成环
  iptables -t nat -A ARTEX_DNS -d 127.0.0.1/32 -j RETURN || return 1
  iptables -t nat -A ARTEX_DNS -p udp --dport 53 -j REDIRECT --to-ports 53 || return 1
  iptables -t nat -A ARTEX_DNS -p tcp --dport 53 -j REDIRECT --to-ports 53 || return 1
  iptables -t nat -C OUTPUT -j ARTEX_DNS 2>/dev/null || iptables -t nat -A OUTPUT -j ARTEX_DNS || return 1
  return 0
}

if install_dns_redirect; then
  echo "[entry] DNS 已重定向到 Tor DNSPort (127.0.0.1:53)"
else
  echo "[entry] 警告: DNS 重定向规则安装失败（缺 NET_ADMIN 或 iptables）" >&2
fi

exec /app/start.sh "$@"
