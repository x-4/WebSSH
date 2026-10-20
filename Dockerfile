# syntax=docker/dockerfile:1

# ---------- 构建阶段：安装生产依赖（含 node-pty 原生编译） ----------
ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-bookworm-slim AS deps
WORKDIR /app

# node-pty 需要现场编译；构建工具只存在于本阶段，不进最终镜像
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

# ---------- 运行阶段 ----------
FROM node:${NODE_VERSION}-bookworm-slim AS runtime

LABEL org.opencontainers.image.title="WebSSH" \
      org.opencontainers.image.description="Browser-based SSH and local terminal with audit, RBAC and session recording"

# tini 作为 PID 1 转发信号并回收僵尸进程；gosu 用于入口脚本降权
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    HOME=/home/node \
    NODE_OPTIONS=--max-old-space-size=768

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json server.js ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
COPY --chown=node:node scripts/hash-password.js scripts/user.js ./scripts/
COPY --chown=node:node docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && mkdir -p /app/data \
    && chown node:node /app/data \
    && chmod 700 /app/data

EXPOSE 3000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "-e", "require('http').get('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["node", "server.js"]
