# ==============================================================================
# PHP Text Intelligence - Production Dockerfile
#
# Multi-stage build:
#   1. Build custom Caddy with rate limiting module
#   2. Build frontend
#   3. Install PHP dependencies
#   4. Runtime with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build custom Caddy with rate limiting module
FROM golang:1.25-alpine AS caddy-builder
WORKDIR /build
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/mholt/caddy-ratelimit
# Binary output: /build/caddy

# Stage 2: Build frontend
FROM node:24-slim AS frontend-builder
RUN corepack enable
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./frontend/
RUN cd frontend && pnpm install --frozen-lockfile
COPY frontend/ ./frontend/
RUN cd frontend && pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./frontend/dist/index.html

# Stage 3: Install PHP dependencies
FROM composer:2 AS php-builder
WORKDIR /build
COPY composer.json ./
RUN composer install --no-dev --optimize-autoloader

# Stage 4: Runtime
FROM php:8.3-cli-alpine

# Copy custom Caddy binary
COPY --from=caddy-builder /build/caddy /usr/bin/caddy

# Install curl extension for PHP
RUN apk add --no-cache curl

WORKDIR /app

# Copy PHP dependencies
COPY --from=php-builder /build/vendor ./vendor

# Copy backend source and config
COPY server.php deepgram.toml sample.env ./

# Copy built frontend
COPY --from=frontend-builder /build/frontend/dist/ ./frontend/dist/

# Copy shared deployment files
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

ENV PORT=8081
ENV HOST=0.0.0.0
EXPOSE 8080

ENV BACKEND_CMD="php -S 0.0.0.0:8081 server.php"
CMD ["./start.sh"]
