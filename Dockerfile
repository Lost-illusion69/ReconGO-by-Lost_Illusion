# syntax=docker/dockerfile:1.7

# ==============================================================================
# Stage 1 — Builder
# ==============================================================================
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependency downloads separately from source copies.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev

# Statically linked Linux binary — no CGO, no libc dependency at link time.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/recongo \
      ./cmd/recongo

# ==============================================================================
# Stage 2 — Final Runtime
# ==============================================================================
FROM alpine:latest AS runtime

# TLS root CAs for HTTPS API calls and active HTTP probing.
RUN apk add --no-cache ca-certificates \
    && addgroup -S recongo \
    && adduser -S recongo -G recongo -h /app -s /sbin/nologin

WORKDIR /app

COPY --from=builder /out/recongo /app/recongo

# Drop privileges before executing user-supplied flags.
USER recongo:recongo

ENTRYPOINT ["/app/recongo"]
