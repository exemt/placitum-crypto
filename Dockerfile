FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-crypto ./cmd/waf-crypto

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/crypto" \
      org.opencontainers.image.description="Placitum crypto service: opens stored object envelopes with the installation key" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-crypto" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/waf-crypto /usr/local/bin/waf-crypto

RUN adduser -D -H -u 10005 wafcrypto

USER wafcrypto

ENV WAF_CRYPTO_HTTP=:8093

EXPOSE 8093

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8093/healthz || exit 1

CMD ["waf-crypto"]
