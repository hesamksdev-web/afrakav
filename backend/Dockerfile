# ── build stage ──────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS gobuild
WORKDIR /src

# Cache module downloads across rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/afrashodan .

# ── runtime stage ────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app
WORKDIR /app

COPY --from=gobuild /out/afrashodan /app/afrashodan
COPY data/sample.nessus /app/data/sample.nessus

ENV AFRASHODAN_ADDR=:8080 \
    AFRASHODAN_SEED=/app/data/sample.nessus
EXPOSE 8080
USER app

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/afrashodan"]
