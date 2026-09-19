FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
COPY web/package.json web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN npm ci
COPY . .
RUN python3 -m venv /opt/winfire-venv && /opt/winfire-venv/bin/pip install --no-cache-dir -r api/sidecar/requirements.txt
RUN npm run build && npm test

FROM node:24-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 smbclient openssl && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production DATA_DIR=/data PORT=3000 WINRM_PYTHON=/opt/winfire-venv/bin/python
COPY --from=build /opt/winfire-venv /opt/winfire-venv
COPY --from=build /app/package*.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/api ./api
COPY --from=build /app/packages ./packages
COPY --from=build /app/web/dist ./web/dist
VOLUME /data
EXPOSE 3000
CMD ["node","api/src/server.js"]
