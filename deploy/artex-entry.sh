#!/bin/sh
# 容器出口：目标 TCP/DNS 强制经 Tor；显式平台 IP 和 Tor 自身可直连。
# 防火墙先安装拒绝规则，再安装透明重定向。任何失败都不启动应用。
set -eu

TOR_UID="$(id -u artestor)"
CLASH_UID=""
if [ "${ARTEX_CLASH_ENABLED:-0}" = "1" ]; then
  CLASH_UID="$(id -u clash)"
fi

install_rules() {
  command -v iptables-restore >/dev/null 2>&1 || return 1
  command -v ip6tables-restore >/dev/null 2>&1 || return 1
  # 只接受 IPv4 地址，避免错误白名单或换行被当作防火墙指令。
  direct_ips=$(python3 - <<'PY'
import ipaddress, os, re
for value in re.split(r"[\s,]+", os.environ.get("ARTEX_DIRECT_IPS", "").strip()):
    if value:
        address = ipaddress.IPv4Address(value)
        print(address)
PY
  ) || return 1

  # 透明代理后的包目的地为回环地址，才被允许。NAT 丢失时也不能直接出网。
  {
    echo '*filter'
    echo ':ARTEX_DROP - [0:0]'
    echo '-F ARTEX_DROP'
    if iptables -C OUTPUT -j ARTEX_DROP 2>/dev/null; then
      echo '-D OUTPUT -j ARTEX_DROP'
    fi
    echo '-I OUTPUT 1 -j ARTEX_DROP'
    echo "-A ARTEX_DROP -m owner --uid-owner $TOR_UID -j RETURN"
    if [ -n "$CLASH_UID" ]; then
      echo "-A ARTEX_DROP -m owner --uid-owner $CLASH_UID -j RETURN"
    fi
    for ip in $direct_ips; do
      echo "-A ARTEX_DROP -d $ip -m comment --comment artex-direct -j RETURN"
    done
    # Tor DNSPort 只支持 UDP，TCP DNS 必须拒绝，不能落到同号 SOCKS 端口。
    echo '-A ARTEX_DROP -p tcp --dport 53 -j REJECT'
    echo '-A ARTEX_DROP -o lo -j RETURN'
    echo '-A ARTEX_DROP -d 127.0.0.0/8 -j RETURN'
    echo '-A ARTEX_DROP -d 172.16.0.0/12 -j RETURN'
    echo '-A ARTEX_DROP -d 10.0.0.0/8 -j RETURN'
    echo '-A ARTEX_DROP -d 192.168.0.0/16 -j RETURN'
    echo '-A ARTEX_DROP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
    echo '-A ARTEX_DROP -j REJECT'
    echo 'COMMIT'
  } | iptables-restore --noflush || return 1

  # IPv6 没有透明转发通道，应用只允许回环和已建立的入站连接。
  {
    echo '*filter'
    echo ':ARTEX6_DROP - [0:0]'
    echo '-F ARTEX6_DROP'
    if ip6tables -C OUTPUT -j ARTEX6_DROP 2>/dev/null; then
      echo '-D OUTPUT -j ARTEX6_DROP'
    fi
    echo '-I OUTPUT 1 -j ARTEX6_DROP'
    echo "-A ARTEX6_DROP -m owner --uid-owner $TOR_UID -j RETURN"
    if [ -n "$CLASH_UID" ]; then
      echo "-A ARTEX6_DROP -m owner --uid-owner $CLASH_UID -j RETURN"
    fi
    echo '-A ARTEX6_DROP -o lo -j RETURN'
    echo '-A ARTEX6_DROP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
    echo '-A ARTEX6_DROP -j REJECT'
    echo 'COMMIT'
  } | ip6tables-restore --noflush || return 1

  {
    echo '*nat'
    echo ':ARTEX_TP - [0:0]'
    echo '-F ARTEX_TP'
    if iptables -t nat -C OUTPUT -j ARTEX_TP 2>/dev/null; then
      echo '-D OUTPUT -j ARTEX_TP'
    fi
    # 先于 Docker 的 127.0.0.11 DNS DNAT，防止工具自选解析器绕过 Tor。
    echo '-I OUTPUT 1 -j ARTEX_TP'
    echo "-A ARTEX_TP -m owner --uid-owner $TOR_UID -j RETURN"
    if [ -n "$CLASH_UID" ]; then
      echo "-A ARTEX_TP -m owner --uid-owner $CLASH_UID -j RETURN"
    fi
    for ip in $direct_ips; do
      echo "-A ARTEX_TP -d $ip -m comment --comment artex-direct -j RETURN"
    done
    echo '-A ARTEX_TP -p udp --dport 53 -j REDIRECT --to-ports 19053'
    echo '-A ARTEX_TP -p tcp --dport 53 -j RETURN'
    echo '-A ARTEX_TP -o lo -j RETURN'
    echo '-A ARTEX_TP -d 127.0.0.0/8 -j RETURN'
    echo '-A ARTEX_TP -d 172.16.0.0/12 -j RETURN'
    echo '-A ARTEX_TP -d 10.0.0.0/8 -j RETURN'
    echo '-A ARTEX_TP -d 192.168.0.0/16 -j RETURN'
    echo '-A ARTEX_TP -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
    echo '-A ARTEX_TP -p tcp -j REDIRECT --to-ports 9040'
    echo 'COMMIT'
  } | iptables-restore --noflush || return 1
}

start_clash() {
  # DIRECT 占位配置不再默认开放备用出口；显式启用时保留人工切换能力。
  [ "${ARTEX_CLASH_ENABLED:-0}" = "1" ] || return 0
  if ! /usr/local/bin/artex-clash-restart.sh; then
    echo '[entry] Clash 不可用；Tor 主服务继续启动，指定 Clash 的请求将被拒绝' >&2
  fi
}

if [ "${1:-}" = "--refresh-rules" ]; then
  install_rules
  exit $?
fi

if [ "${ARTEX_TRANSPARENT_TOR:-1}" = "0" ]; then
  echo '[entry] 显式关闭透明代理；仅用于排障' >&2
elif install_rules; then
  echo '[entry] Tor 防护已启用：TCP->9040，DNS->19053，其余公网流量拒绝'
else
  echo '[entry] Tor 防火墙安装失败，拒绝启动应用（需要 NET_ADMIN 和 IPv4/IPv6 iptables）' >&2
  exit 78
fi

start_clash
exec /app/start.sh "$@"
