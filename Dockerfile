FROM golang:1.14-alpine AS builder
RUN apk add --no-cache git
RUN GO111MODULE=auto go get -u -v github.com/projectdiscovery/httpx/cmd/httpx

FROM alpine:latest
COPY --from=builder /go/bin/httpx /usr/local/bin/

ENTRYPOINT ["httpx"]
