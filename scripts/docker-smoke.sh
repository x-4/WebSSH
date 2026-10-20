#!/usr/bin/env bash
# Docker 冒烟测试：构建镜像 → 以生产参数启动 → 健康/就绪/登录/本机 PTY 校验。
# 用法：bash scripts/docker-smoke.sh
set -euo pipefail

IMAGE="${IMAGE:-webssh:smoke}"
NODE_VERSION="${NODE_VERSION:-22}"
PORT="${PORT:-$((39000 + (RANDOM % 1000)))}"
NAME="webssh-smoke-$$"
VOLUME="webssh-smoke-data-$$"
COOKIE="$(mktemp)"
BASE="http://127.0.0.1:${PORT}"
if [ -n "${SESSION_SECRET:-}" ]; then
  SECRET="$SESSION_SECRET"
elif command -v openssl >/dev/null 2>&1; then
  SECRET="$(openssl rand -hex 32)"
else
  SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  rm -f "$COOKIE"
}
trap cleanup EXIT

echo "==> 构建镜像 ${IMAGE}（Node ${NODE_VERSION}）"
docker build --build-arg "NODE_VERSION=${NODE_VERSION}" -t "$IMAGE" .

echo "==> 创建数据卷并启动容器"
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$NAME" \
  -p "127.0.0.1:${PORT}:3000" \
  -e NODE_ENV=production \
  -e WEBSSH_USER=admin \
  -e WEBSSH_PASS=smoke-pass-123 \
  -e SESSION_SECRET="$SECRET" \
  -e LOCAL_TERMINAL_ENABLED=true \
  -v "${VOLUME}:/app/data" \
  --read-only \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  --tmpfs /home/node:size=64m,uid=1000,gid=1000,mode=0700 \
  "$IMAGE" >/dev/null

echo "==> 等待健康检查"
code=""
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" || true)"
  [ "$code" = "200" ] && break
  if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "容器已退出" >&2
    docker logs "$NAME" >&2 || true
    exit 1
  fi
  sleep 1
done
if [ "$code" != "200" ]; then
  echo "健康检查未通过（HTTP ${code}）" >&2
  docker logs "$NAME" >&2 || true
  exit 1
fi

echo "==> 就绪探针"
curl -fsS "${BASE}/readyz" | grep '"ok":true' >/dev/null

echo "==> 登录与接口"
curl -fsS -c "$COOKIE" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"smoke-pass-123"}' \
  "${BASE}/api/login" | grep '"ok":true' >/dev/null
curl -fsS -b "$COOKIE" "${BASE}/api/config" | grep '"available":true' >/dev/null
curl -fsS -o /dev/null -w '%{http_code}' "${BASE}/metrics" | grep '^200$' >/dev/null

echo "==> 进程降权检查"
docker top "$NAME" -o user | grep 'node' >/dev/null

echo "Docker 冒烟测试通过 ✅"
