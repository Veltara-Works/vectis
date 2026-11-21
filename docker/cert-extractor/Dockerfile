FROM golang:1.27-alpine AS builder

ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags netgo,osusergo \
    -ldflags="-s -w -X github.com/Veltara-Works/vectis/internal/version.Version=${VERSION}" \
    -o /vectis ./cmd/vectis/

FROM alpine:3.24

# docker-cli is required at runtime so the extractor can reload
# vectis-postfix / vectis-dovecot when the cert rotates. The container
# must be given /var/run/docker.sock by the compose template.
# PKG_REFRESH changes on every workflow run (release.yml / trivy.yml pass the
# run id), so the GHA layer cache can never replay a stale package upgrade:
# this layer and the ones after it rebuild; earlier build stages stay cached.
ARG PKG_REFRESH=local
# Upgrade the base's packages too (OpenSSL, zlib, ...): alpine:3.24 is only
# re-tagged now and then, so without this a rebuild ships stale libraries.
RUN echo "package refresh: ${PKG_REFRESH}" && apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata docker-cli

COPY --from=builder /vectis /usr/local/bin/vectis

ENTRYPOINT ["vectis", "tls", "extract-traefik"]
CMD ["--watch"]
