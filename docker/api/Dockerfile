FROM node:22 AS web-builder

# Debian-based image (not alpine) so native modules like lightningcss
# get their glibc binary from npm's optionalDependencies. The Alpine
# variant intermittently fails because lightningcss-linux-x64-musl
# isn't always pinned in package-lock and npm ci skips optionals it
# doesn't know about. Output is static files — base image doesn't
# matter past the COPY into the alpine stage below.
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS builder

ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags netgo,osusergo \
    -ldflags="-s -w -X github.com/Veltara-Works/vectis/internal/version.Version=${VERSION}" \
    -o /vectis ./cmd/vectis/

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata wget postgresql17-client tar

COPY --from=builder /vectis /usr/local/bin/vectis
COPY --from=web-builder /web/dist /usr/share/vectis/web

# Config and data volumes
VOLUME ["/etc/vectis", "/var/vectis/mail", "/var/vectis/dkim"]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["vectis"]
CMD ["serve", "--web-dir=/usr/share/vectis/web"]
