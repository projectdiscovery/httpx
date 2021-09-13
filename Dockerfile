FROM golang:1.17.1-alpine AS builder
RUN apk add --no-cache git
RUN GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx

FROM alpine:3.14
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /go/bin/httpx /usr/local/bin/

ENTRYPOINT ["httpx"]
