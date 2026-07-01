BINARY := neurosploit
GO := go
GOLANGCI_LINT := golangci-lint
GORELEASER := goreleaser

REPO_ROOT := $(abspath .)
GO_SOURCE_DIR := $(REPO_ROOT)/neurosploit-go
AGENTS_SRC := $(REPO_ROOT)/agents_md
VERSION ?= $(shell git -C $(GO_SOURCE_DIR) describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_TAGS := embed_agents

.PHONY: all build build-release release sync-agents test lint fmt vet check clean goreleaser-snapshot goreleaser-check

all: build

build:
	cd $(GO_SOURCE_DIR) && $(GO) build -o $(BINARY) ./cmd/neurosploit

sync-agents:
	@test -d $(AGENTS_SRC) || (echo "agents_md not found at $(AGENTS_SRC)" && exit 1)
	rsync -a --delete $(AGENTS_SRC)/ $(GO_SOURCE_DIR)/internal/agents/agentsdata/

build-release: sync-agents
	cd $(GO_SOURCE_DIR) && $(GO) build -tags $(BUILD_TAGS) -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY) ./cmd/neurosploit

release: build-release

test:
	cd $(GO_SOURCE_DIR) && $(GO) test ./... -timeout 30s

lint:
	cd $(GO_SOURCE_DIR) && $(GOLANGCI_LINT) run ./...

fmt:
	cd $(GO_SOURCE_DIR) && $(GO) fmt ./...

vet:
	cd $(GO_SOURCE_DIR) && $(GO) vet ./...

run: build
	cd $(GO_SOURCE_DIR) && ./$(BINARY) run $(ARGS)

tui: build
	cd $(GO_SOURCE_DIR) && ./$(BINARY) tui $(ARGS)

repl: build
	cd $(GO_SOURCE_DIR) && ./$(BINARY)

check: fmt vet test build-release

goreleaser-check:
	cd $(GO_SOURCE_DIR) && $(GORELEASER) check

goreleaser-snapshot:
	cd $(GO_SOURCE_DIR) && $(GORELEASER) release --snapshot --clean

clean:
	rm -f $(BINARY)
	rm -rf $(GO_SOURCE_DIR)/dist
