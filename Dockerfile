FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="httpx"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/httpx"

RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates chromium

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/httpx /usr/local/bin/

ENTRYPOINT ["httpx"]
