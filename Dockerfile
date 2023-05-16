# Base
FROM golang:1.20.4-alpine AS builder

RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/httpx

FROM alpine:3.18.0
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates chromium
COPY --from=builder /app/httpx /usr/local/bin/

ENTRYPOINT ["httpx"]