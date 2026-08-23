FROM node:24-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . ./

ARG VITE_API_BASE_URL=""
ARG VITE_DEMO_ENABLED="false"
ARG VITE_MAX_APK_MB="75"
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL} \
    VITE_DEMO_ENABLED=${VITE_DEMO_ENABLED} \
    VITE_MAX_APK_MB=${VITE_MAX_APK_MB}
RUN npm run check

FROM nginx:1.28-alpine AS runtime

LABEL org.opencontainers.image.title="FraudShield DeceptiScope" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.description="Evidence-grounded multi-engine APK analysis frontend"

COPY --from=builder --chown=101:101 /app/dist /usr/share/nginx/html
COPY --chown=101:101 nginx.conf.template /etc/nginx/templates/default.conf.template
RUN rm -f /etc/nginx/conf.d/default.conf \
    && chown -R 101:101 /etc/nginx/conf.d /var/cache/nginx /var/run

ENV FRAUDSHIELD_API_UPSTREAM=http://fraudshield-api:8000
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
