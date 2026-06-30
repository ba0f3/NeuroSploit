BINARY := neurosploit
GO := go
GOLANGCI_LINT := golangci-lint
GORELEASER := goreleaser

REPO_ROOT := $(abspath ..)
AGENTS_SRC := $(REPO_ROOT)/agents_md
AGENTS_DST := internal/agents/agentsdata
VERSION ?= $(shell git -C $(REPO_ROOT) describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_TAGS := embed_agents

.PHONY: all build build-release release sync-agents test lint fmt vet check clean goreleaser-snapshot goreleaser-check

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/neurosploit

sync-agents:
	@test -d $(AGENTS_SRC) || (echo "agents_md not found at $(AGENTS_SRC)" && exit 1)
	rsync -a --delete $(AGENTS_SRC)/ $(AGENTS_DST)/

build-release: sync-agents
	$(GO) build -tags $(BUILD_TAGS) -ldflags "$(LDFLAGS)" -trimpath -o $(BINARY) ./cmd/neurosploit

release: build-release

test:
	$(GO) test ./... -timeout 30s

lint:
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

check: fmt vet test build-release

goreleaser-check:
	cd $(REPO_ROOT) && $(GORELEASER) check

goreleaser-snapshot:
	cd $(REPO_ROOT) && $(GORELEASER) release --snapshot --clean

clean:
	rm -f $(BINARY)
	rm -rf $(REPO_ROOT)/dist
