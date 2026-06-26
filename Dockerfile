# Build stage
FROM golang:1.25-alpine AS builder

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
COPY config/params.json ./config/
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8082 9090

ENTRYPOINT ["/entrypoint.sh"]
