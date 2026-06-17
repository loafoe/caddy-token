# Build metadata injected into the caddy-token-gen binary.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build install test

# Build the CLI into ./bin with version metadata.
build:
	go build -ldflags "$(LDFLAGS)" -o bin/caddy-token-gen ./cmd/caddy-token-gen

# Install the CLI into $GOBIN (or $GOPATH/bin) with version metadata.
install:
	go build -ldflags "$(LDFLAGS)" -o $(or $(GOBIN),$(shell go env GOPATH)/bin)/caddy-token-gen ./cmd/caddy-token-gen

test:
	go test ./...
