FROM node:24-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-pip smbclient openssl make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
COPY web/package.json web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN npm ci --omit=dev
COPY api ./api
COPY packages ./packages
RUN python3 -m venv /opt/winfire-venv && /opt/winfire-venv/bin/pip install --no-cache-dir -r api/sidecar/requirements.txt
ENV NODE_ENV=production DATA_DIR=/data PORT=3000 HOST=0.0.0.0 WINRM_PYTHON=/opt/winfire-venv/bin/python
VOLUME /data
EXPOSE 3000
CMD ["node", "api/src/server.js"]
