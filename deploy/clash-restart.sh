#!/bin/sh
# 容器内：严格编译节点配置并以独立 UID 启动 Mihomo。
set -eu
umask 077
DIR="${ARTEX_CLASH_DIR:-/var/lib/artex-clash}"
CFG="$DIR/config.yaml"
BIN=/usr/local/bin/mihomo
CONFIG_TOOL=/usr/local/bin/artex-clash-config.py

[ "${ARTEX_CLASH_ENABLED:-0}" = "1" ] || { echo '[clash] 未启用，保持拒绝' >&2; exit 2; }
[ -x "$BIN" ] || { echo '[clash] 未安装 mihomo' >&2; exit 1; }
mkdir -p "$DIR"
chmod 700 "$DIR"
exec 9>"$DIR/.restart.lock"
flock -x 9

# 已持久化的节点优先；旧 data/clash 仅安全读取迁移，不覆盖旧文件。
/usr/bin/python3 "$CONFIG_TOOL" prepare --directory "$DIR"
chown -R clash:clash "$DIR"
chmod 600 "$CFG" "$DIR/controller.secret"

for p in /proc/[0-9]*; do
  if [ "$(cat "$p/comm" 2>/dev/null)" = 'mihomo' ]; then
    kill "${p#/proc/}" 2>/dev/null || true
  fi
done
i=0
while [ "$i" -lt 30 ]; do
  alive=0
  for p in /proc/[0-9]*; do
    if [ "$(cat "$p/comm" 2>/dev/null)" = 'mihomo' ]; then alive=1; fi
  done
  [ "$alive" = '0' ] && break
  i=$((i+1))
  sleep 0.2
done
if [ "$alive" != '0' ]; then
  echo '[clash] 旧实例未停止，拒绝启动第二个实例' >&2
  exit 1
fi

# 不向日志/终端输出 controller secret 或节点配置。
setpriv --reuid clash --regid clash --init-groups "$BIN" -d "$DIR" -f "$CFG" >>"$DIR/mihomo.log" 2>&1 9>&- &
echo "$!" >"$DIR/mihomo.pid"
i=0
while [ "$i" -lt 30 ]; do
  if /usr/bin/python3 - "$DIR" <<'CLASH_CHECK'
from pathlib import Path
import sys, urllib.request
try:
    secret = (Path(sys.argv[1]) / 'controller.secret').read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request('http://127.0.0.1:9090/version', headers={'Authorization': 'Bearer ' + secret})
    with opener.open(req, timeout=0.5) as response:
        assert response.status == 200
except Exception:
    sys.exit(1)
CLASH_CHECK
  then
    echo '[clash] 已启动严格代理入口 127.0.0.1:7890；无节点时只拒绝连接'
    exit 0
  fi
  i=$((i+1))
  sleep 0.3
done
echo '[clash] 启动失败；Clash 请求保持拒绝，详情仅保存在私密日志' >&2
exit 1
