BINARY := neurosploit
GO := go
GOLANGCI_LINT := golangci-lint

.PHONY: all build test lint fmt vet check clean

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/neurosploit

test:
	$(GO) test ./... -timeout 30s

lint:
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

check: fmt vet lint test

clean:
	rm -f $(BINARY)
