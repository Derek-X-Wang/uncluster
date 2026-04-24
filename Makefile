.PHONY: build test lint tidy clean

VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -s -w -X github.com/derek-x-wang/uncluster/internal/version.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o uncluster ./cmd/uncluster

test:
	go test ./... -race -count=1

lint:
	@pkgs=$$(go list ./... 2>/dev/null); \
	if [ -z "$$pkgs" ]; then \
		echo "no packages; skipping vet"; \
	else \
		go vet ./...; \
	fi
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./... 2>/dev/null || true; else echo "staticcheck not installed; skipping"; fi

tidy:
	go mod tidy

clean:
	rm -rf ./uncluster ./dist ./coverage.out ./coverage.html
