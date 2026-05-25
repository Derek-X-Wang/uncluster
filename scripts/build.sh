#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
OUT="${OUT:-dist}"
mkdir -p "$OUT"

LDFLAGS="-s -w -X github.com/derek-x-wang/uncluster/internal/version.Version=${VERSION}"

targets=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  [[ "$os" == "windows" ]] && ext=".exe"
  bin="uncluster-${os}-${arch}${ext}"
  echo "building ${bin} (VERSION=${VERSION})"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${bin}" ./cmd/uncluster
done

echo "done: $(ls -lh "${OUT}")"
