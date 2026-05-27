# syntax=docker/dockerfile:1.6
# Agent image: real OpenSSH server + the uncluster binary.
# The entrypoint waits for the Control plane, joins, configures sshd with the
# CA pubkey and AuthorizedPrincipalsFile, starts sshd in foreground, and then
# runs `uncluster agent run` alongside. No systemd in the container — sshd is
# the foreground process (per T1a slice scope, no service installation).
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
       ca-certificates curl tini openssh-server jq \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/ssh/auth_principals \
    && chmod 0755 /etc/ssh/auth_principals

# Create the test target user that Callers will SSH into.
ARG TARGET_USER=tester
RUN useradd --create-home --shell /bin/bash "${TARGET_USER}" \
    && passwd -d "${TARGET_USER}"
ENV TARGET_USER=${TARGET_USER}

COPY --from=build /out/uncluster /usr/local/bin/uncluster
COPY test/e2e/compose/entrypoints/agent.sh /usr/local/bin/agent-entrypoint.sh
RUN chmod +x /usr/local/bin/agent-entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agent-entrypoint.sh"]
