FROM golang:1.27-alpine AS builder

ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags netgo,osusergo \
    -ldflags="-s -w -X github.com/Veltara-Works/vectis/internal/version.Version=${VERSION}" \
    -o /orchestrator ./cmd/orchestrator/

FROM alpine:3.24

# Upgrade the base's packages too (OpenSSL, zlib, ...): alpine:3.24 is only
# re-tagged now and then, so without this a rebuild ships stale libraries.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata docker-cli docker-cli-compose postgresql17-client

COPY --from=builder /orchestrator /usr/local/bin/orchestrator

# Config (read-only mount) and snapshot storage
VOLUME ["/etc/vectis", "/var/vectis/snapshots"]

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO /dev/null http://localhost:8081/internal/health || exit 1

ENTRYPOINT ["orchestrator"]
