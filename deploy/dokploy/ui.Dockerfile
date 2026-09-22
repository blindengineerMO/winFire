FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
COPY web/package.json web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN npm ci
COPY web ./web
COPY packages ./packages
RUN npm run build -w web

FROM nginx:1.27-alpine
COPY deploy/dokploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/web/dist /usr/share/nginx/html
EXPOSE 80
