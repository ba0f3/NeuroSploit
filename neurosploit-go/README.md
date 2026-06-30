# NeuroSploit Go Harness

This is the Go port of the NeuroSploit multi-model autonomous pentest harness.

## Quick Start

```bash
cd neurosploit-go
go build ./cmd/neurosploit
./neurosploit --help
./neurosploit models
./neurosploit run http://example.com --offline --max-agents 3 -v
```

## Layout

- `cmd/neurosploit` — CLI entry point.
- `internal/types` — shared data structures (`Finding`, `RunConfig`).
- `internal/agents` — markdown agent library loader.
- `internal/belief` — probabilistic world model.
- `internal/pomdp` — belief planner and action selector.
- `internal/pool` — model pool with failover and voting.
- `internal/models` — LLM provider registry and HTTP/CLI clients.
- `internal/creds` — `creds.yaml` parser and login flow.
- `internal/grounding` — evidence receipt gate.
- `internal/hygiene` — severity calibration.
- `internal/attackgraph` — CWE→kill-chain enrichment.
- `internal/registry` — JSONL findings store.
- `internal/pipeline` — engagement orchestrator.
- `internal/repl` — interactive slash-command REPL.
- `internal/tui` — setup wizard and menu helpers.
- `internal/mcpbridge` — local MCP tool registry.
- `internal/rl` — reinforcement-learning reward tracker.

## Testing

```bash
go test ./... -timeout 30s
go vet ./...
```

## Release build

Embedded agents (no `agents_md/` on disk required):

```bash
make build-release    # sync agents_md → agentsdata, build with -tags embed_agents
make release          # alias for build-release
./neurosploit --version
```

From the repo root, cut a release with [GoReleaser](https://goreleaser.com):

```bash
# local snapshot (no publish)
cd neurosploit-go && make goreleaser-snapshot

# tag push triggers .github/workflows/go-release.yml
git tag v3.6.0 && git push origin v3.6.0
```

## Documentation

- `docs/AGENTS.md` — contributor guide for agent authors.
- `docs/PARITY.md` — Rust→Go parity mapping and deviation log.
