#!/bin/sh
# 宿主机获取订阅；容器内安全解析，只导入实际代理节点。
# 用法：./deploy/clash-set-subscription.sh <https订阅URL> [容器名]
#       ./deploy/clash-set-subscription.sh --file <本地YAML> [容器名]
set -eu
umask 077
caller_dir=$(pwd)
cd "$(dirname "$0")/.."
source="${1:?请提供订阅URL，或使用 --file 本地YAML路径}"
file=''
if [ "$source" = '--file' ]; then
  file="${2:?--file 需要本地YAML路径}"
  case "$file" in /*) ;; *) file="$caller_dir/$file" ;; esac
  container="${3:-}"
else
  container="${2:-}"
  case "$source" in
    http://*|https://*) ;;
    *) echo '[clash] 订阅需为 HTTP(S) URL；本地文件请使用 --file' >&2; exit 2 ;;
  esac
fi
if [ -z "$container" ]; then container=$(docker compose ps -q artex); fi
[ -n "$container" ] || { echo '[clash] 应用容器尚未运行' >&2; exit 2; }

tmp=$(mktemp "${TMPDIR:-/tmp}/artex-clash.XXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM
if [ -n "$file" ]; then
  cat "$file" >"$tmp"
else
  # 订阅属于管理流量，宿主机下载；节点密钥不进入终端输出。
  curl -fsSL --max-time 60 --max-filesize 8388608 -A 'clash-verge/v1.7' -o "$tmp" "$source"
fi
docker exec -i "$container" /usr/bin/python3 /usr/local/bin/artex-clash-config.py import <"$tmp"
docker exec "$container" /usr/local/bin/artex-clash-restart.sh
