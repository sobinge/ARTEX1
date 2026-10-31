#!/bin/sh
# tor 启动垫片（torpool 以 `tor -f <torrc>` 调用）：
# slot 1 额外在 127.0.0.1:53 上提供 DNSPort，供容器 /etc/resolv.conf 指向 Tor，
# 避免工具用 libc 解析域名时泄漏给本地解析器。其余 slot 行为不变。
case "$*" in
  *"/tor-01/torrc"*) exec /usr/sbin/tor.real "$@" --DNSPort 127.0.0.1:53 --AutomapHostsOnResolve 1 ;;
esac
exec /usr/sbin/tor.real "$@"
