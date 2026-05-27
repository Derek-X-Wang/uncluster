# syntax=docker/dockerfile:1.6
# Shared builder: compiles the uncluster binary once, copied into role images.
# Pinned Go version aligns with go.mod (1.25) and CI matrix setup-go@v5.
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Cache module downloads in a separate layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Build the static binary used by every role.
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
      -o /out/uncluster ./cmd/uncluster
