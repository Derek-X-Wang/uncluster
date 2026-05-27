# syntax=docker/dockerfile:1.6
# Control plane image: thin runtime around the uncluster binary.
# Boots the server in foreground, persists CA + SQLite in /var/lib/uncluster.
FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
      -o /out/uncluster ./cmd/uncluster

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/uncluster /usr/local/bin/uncluster
COPY test/e2e/compose/entrypoints/cp.sh /usr/local/bin/cp-entrypoint.sh
RUN chmod +x /usr/local/bin/cp-entrypoint.sh

ENV UNCLUSTER_DATA_DIR=/var/lib/uncluster \
    UNCLUSTER_DB=/var/lib/uncluster/uncluster.db \
    UNCLUSTER_CA=/var/lib/uncluster/ca

EXPOSE 7777

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cp-entrypoint.sh"]
