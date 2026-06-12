FROM golang:1.26-alpine AS builder

ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags netgo,osusergo \
    -ldflags="-s -w -X github.com/Veltara-Works/vectis/internal/version.Version=${VERSION}" \
    -o /vectis ./cmd/vectis/

FROM alpine:3.24

# docker-cli is required at runtime so the extractor can SIGHUP
# vectis-postfix / vectis-dovecot when the cert rotates. The container
# must be given /var/run/docker.sock by the compose template.
RUN apk add --no-cache ca-certificates tzdata docker-cli

COPY --from=builder /vectis /usr/local/bin/vectis

ENTRYPOINT ["vectis", "tls", "extract-traefik"]
CMD ["--watch"]
