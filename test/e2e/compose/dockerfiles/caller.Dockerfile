# syntax=docker/dockerfile:1.6
# Caller image: uncluster CLI + OpenSSH client. Idles indefinitely; the test
# harness shells into it and drives `uncluster ssh ...` calls.
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
    && apt-get install -y --no-install-recommends \
       ca-certificates curl tini openssh-client jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/uncluster /usr/local/bin/uncluster
COPY test/e2e/compose/entrypoints/caller.sh /usr/local/bin/caller-entrypoint.sh
RUN chmod +x /usr/local/bin/caller-entrypoint.sh

ENV UNCLUSTER_CALLER_DIR=/var/lib/uncluster-caller

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/caller-entrypoint.sh"]
