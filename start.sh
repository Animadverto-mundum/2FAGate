#!/usr/bin/env bash
# 启动 2FAGate 容器:构建镜像并以后台方式拉起,随后打印登录二维码
set -euo pipefail

cd "$(dirname "$0")"

# 选择可用的 compose 命令(优先 docker compose,回退 podman-compose / docker-compose)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
  COMPOSE="podman-compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "错误:未找到 docker compose / podman-compose / docker-compose,请先安装。" >&2
  exit 1
fi

echo ">> 使用 compose 命令:$COMPOSE"
echo ">> 构建并启动容器..."
$COMPOSE up -d --build

echo
echo ">> 容器状态:"
$COMPOSE ps

echo
echo ">> 登录二维码(用验证器 App 扫描;若已有密钥则无需重新扫描):"
$COMPOSE logs auth 2>&1 | grep -E '█|=== Or enter secret' || \
  echo "(暂未输出二维码,可稍后执行:$COMPOSE logs auth)"

echo
echo ">> 完成。服务监听 127.0.0.1:18080"
