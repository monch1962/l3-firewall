# Build stage
# Pinned to a PATCH release on purpose (R97): go1.25.0 reports 49 reachable
# standard-library advisories via govulncheck (crypto/x509, net/http, net/mail,
# encoding/asn1, ...); the fixes landed in 1.25.2/1.25.3. `golang:1.25-alpine`
# floats with the 1.25 line, so a base-image refresh could silently move the
# build back to a vulnerable patch.
FROM golang:1.25.3-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o l3-firewall ./cmd/server/

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata nftables

WORKDIR /app
COPY --from=builder /app/l3-firewall .
COPY --from=builder /app/opa-policies/ ./opa-policies/
COPY config/README.md ./config/
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8082 9090

ENTRYPOINT ["/entrypoint.sh"]
