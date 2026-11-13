FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.30.6-alpine3.24-slim@sha256:f65ed258206d1eb6c4eb6141111715a2cf94ac0a4ec9675fc2da186f7aadb163
# CVE-2026-4738 is fixed in Alpine zlib 1.4-r0; keep the runtime base
# digest-pinned and explicitly require the fixed zlib package revision.
RUN apk add --no-cache 'zlib=1.4-r0' && \
    apk info -v | grep -Fx 'zlib-1.4-r0'
COPY --chown=101:101 --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN set -eux; \
    sed -i 's|/var/log/nginx/error.log|/dev/stderr|g; s|/var/log/nginx/access.log|/dev/stdout|g; s|/run/nginx.pid|/tmp/nginx/nginx.pid|g' /etc/nginx/nginx.conf; \
    mkdir -p /tmp/nginx/client_temp /tmp/nginx/proxy_temp /tmp/nginx/fastcgi_temp /tmp/nginx/uwsgi_temp /tmp/nginx/scgi_temp; \
    chown -R 101:101 /tmp/nginx /var/cache/nginx /var/run /usr/share/nginx/html
USER 101:101
EXPOSE 8080
