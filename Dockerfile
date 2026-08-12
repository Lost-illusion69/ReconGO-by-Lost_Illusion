# syntax=docker/dockerfile:1.7

# ==============================================================================
# Stage 1 — Builder
# ==============================================================================
FROM golang:1.22-alpine AS builder

# Install only the minimum tools required (git for VCS stamping).
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Layer-cache the dependency downloads separately from the source copy.
# This means `go mod download` is re-run only when go.mod / go.sum change.
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Copy the entire project and build the binary.
COPY . .

# CGO_ENABLED=0 produces a fully static binary (no libc dependency).
# -trimpath removes local file-system paths from the binary for reproducibility.
# -ldflags strips the debug symbol table and DWARF info to reduce image size.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
      -o /out/recongo \
      ./cmd/recongo

# ==============================================================================
# Stage 2 — Runtime (scratch for minimal attack surface)
# ==============================================================================
FROM scratch AS runtime

# Pull in TLS root certificates so HTTPS calls to external APIs work.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Drop the binary.
COPY --from=builder /out/recongo /recongo

# Run as a non-root uid by setting the user in the image metadata.
# (scratch has no /etc/passwd so we use numeric UID directly.)
USER 65534:65534

ENTRYPOINT ["/recongo"]
