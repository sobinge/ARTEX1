#!/bin/sh
# 从源码重建并启动。
#
# 为什么需要本地构建：官方镜像最新 tag（v0.3.19, 2026-10-16）早于 Tor 出口功能
# （2026-10-24 feature 提交），镜像里的二进制不含 torpool，也没有 tor 可执行文件。
#
# 用法：./rebuild-local.sh
# 更新代码后：git pull && ./rebuild-local.sh
set -e
cd "$(dirname "$0")"

mkdir -p data
# 绑定挂载的目标必须先存在，否则 Docker 会创建成目录
[ -f data/jwt.key ] || : > data/jwt.key

docker build -t artex-src:local -f Dockerfile .
docker build -t artex-tor:local -f Dockerfile.tor .
docker compose up -d
docker compose ps --format '{{.Name}} {{.Status}}'
