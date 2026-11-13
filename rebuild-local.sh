#!/bin/sh
# 从当前源码构建前端、Go 和 Tor/Clash 运行镜像，并初始化、启动 Docker。
#
# 用法：./rebuild-local.sh
# 更新代码后：git pull && ./rebuild-local.sh
set -eu
cd "$(dirname "$0")"

fail() { echo "[docker] $*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail '未找到 Docker，请先安装 Docker Engine 或 Docker Desktop'
compose_version=$(docker compose version --short 2>/dev/null) || fail '未找到 Docker Compose 插件'
if ! printf '%s\n' "$compose_version" | awk -F. '
  NR == 1 {
    sub(/^v/, "", $1); sub(/[^0-9].*$/, "", $3)
    major = $1 + 0; minor = $2 + 0; patch = $3 + 0
    exit !($1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ &&
      (major > 2 || (major == 2 && (minor > 24 || (minor == 24 && patch >= 4)))))
  }'; then
  fail "需要 Docker Compose >= 2.24.4（当前 ${compose_version}），以支持端口 !override"
fi
docker info >/dev/null 2>&1 || fail 'Docker 服务不可用；请启动 Docker Desktop/Engine，并检查当前用户的 Docker 访问权限'

# 不要求宿主机安装 Go、Node、Python 或 OpenSSL。
random_hex() {
  value=$(od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n')
  [ "${#value}" -eq "$(( $1 * 2 ))" ] || fail '生成随机密钥失败'
  printf '%s\n' "$value"
}

if [ ! -f .env ]; then
  umask 077
  # 只生成本地数据库密码；模型密钥可在首次登录后的 UI 中配置。
  password=$(random_hex 24)
  sed "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$password/" .env.example > .env
  echo '[docker] 已生成 .env（含随机数据库密码）'
fi

mkdir -p data
# 签名密钥位于可浏览工作区 data/ 外，已有密钥保持不变。
if [ ! -f jwt.key ]; then
  umask 077
  if [ -s data/jwt.key ]; then
    cp data/jwt.key jwt.key
  else
    random_hex 32 > jwt.key
  fi
fi

docker compose config --quiet

echo '[docker] 构建当前源码（前端 + Go）'
docker build -t artex-src:local -f Dockerfile .
echo '[docker] 构建 Tor / Clash 运行镜像'
docker build -t artex-tor:local -f Dockerfile.tor .
echo '[docker] 启动服务并等待 Tor 实例池健康'
docker compose up -d --no-build --pull missing --wait --wait-timeout 300
docker compose ps --format '{{.Name}} {{.Status}}'
