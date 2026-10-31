#!/bin/sh
# tor 启动垫片（torpool 以 `tor -f <torrc>` 调用）。
#   1) 所有实例改为 artestor 用户运行：iptables 用 `-m owner --uid-owner artestor`
#      放行 tor 自身流量，其余全部重定向进 TransPort，否则会自己套自己成环。
#   2) slot 1 额外提供 TransPort(9040) 与 DNSPort(19053)，供容器级透明代理使用。
#   3) 启动前把实例目录 chown 给 artestor，否则 tor 拒绝使用 root 拥有的 DataDirectory。
set -u

torrc=""
prev=""
for a in "$@"; do
  [ "$prev" = "-f" ] && torrc="$a"
  prev="$a"
done
if [ -n "$torrc" ]; then
  d=$(dirname "$torrc")
  pool=$(dirname "$d")
  # 必须连 pool 根目录一起 chown：pool 由应用以 root 创建且是 0700，
  # 只改 slot 目录的话 artestor 连穿越都做不到（连 data/ 都会 Permission denied）。
  chown -R artestor:artestor "$pool" 2>/dev/null || true
  chmod 700 "$pool" "$d" 2>/dev/null || true
fi

case "$*" in
  *"/tor-01/torrc"*)
    exec /usr/sbin/tor.real "$@" --User artestor \
      --TransPort 127.0.0.1:9040 --DNSPort 127.0.0.1:19053 --AutomapHostsOnResolve 1 ;;
esac
exec /usr/sbin/tor.real "$@" --User artestor
