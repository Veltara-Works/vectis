FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags netgo,osusergo -ldflags="-s -w" -o /vectis ./cmd/vectis/

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /vectis /usr/local/bin/vectis

# Config and data volumes
VOLUME ["/etc/vectis", "/var/vectis/mail", "/var/vectis/dkim"]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["vectis"]
CMD ["serve"]
