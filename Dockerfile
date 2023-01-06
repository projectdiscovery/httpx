FROM golang:1.19.4-alpine AS builder
ARG BUILD_SOURCE_TAG=latest
RUN apk add --no-cache git build-base gcc musl-dev
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@${BUILD_SOURCE_TAG}

FROM alpine:3.17.0
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /go/bin/httpx /usr/local/bin/

ENTRYPOINT ["httpx"]
