# NeuroSploit Go Agent Contributor Guide

This document describes the Go architecture so that security researchers and agent authors can extend NeuroSploit without reading the whole codebase.

## Repository Layout

```
neurosploit-go/
├── cmd/neurosploit/          # CLI entry point (cobra)
│   └── main.go
└── internal/
    ├── agents/                 # Markdown agent library loader
    ├── attackgraph/          # CWE→kill-chain enrichment + Mermaid/ASCII
    ├── belief/               # Probabilistic world model
    ├── creds/                # creds.yaml parser + auth header/login
    ├── grounding/            # Evidence receipt gate
    ├── hygiene/              # Severity calibration & depth advice
    ├── models/               # LLM provider registry + HTTP/CLI chat client
    ├── mcpbridge/            # Local MCP tool registry
    ├── pipeline/             # Orchestrator (recon → exploit → validate)
    ├── pomdp/                # Belief planner / action selector
    ├── pool/                 # Model pool with failover + voting
    ├── registry/             # JSONL findings store
    ├── repl/                 # Interactive slash-command REPL
    ├── tui/                  # Wizard / menu helpers
    └── types/                # Shared structs (Finding, RunConfig, ...)
```

## Adding a New Agent

Agents are Markdown files under `agents_md/` at the repository root:

- `agents_md/vulns/`     — vulnerability-specific exploit agents
- `agents_md/meta/`      — meta/heuristic agents
- `agents_md/recon/`     — reconnaissance agents
- `agents_md/code/`      — white-box source-review agents
- `agents_md/infra/`     — infrastructure/network agents
- `agents_md/chains/`    — multi-step chaining agents

Each file must contain:

```markdown
# Agent Title

## System Prompt
You are ...

## User Prompt
{{target}}
```

The loader (`internal/agents`) extracts the `#` title, any `CWE-###` reference, and the system/user prompts. No Go code change is required for a new Markdown agent.

## Key Abstractions

### Finding

`internal/types.Finding` is the central data structure. All fields are JSON-serialized with the same names used by the Rust `Finding` struct.

### Pipeline

`pipeline.Run` / `RunWhitebox` / `RunGreybox` / `RunHost` implement the Rust orchestrator:

1. Recon (`pool.Complete` with `TaskRecon`)
2. LLM agent selection (`TaskSelect` + `heuristicSelect` fallback)
3. Parallel exploit per `agents_md` specialist (`agent.System` + `agents.RenderPrompt` on `agent.User`)
4. N-model validation vote
5. Chain round on confirmed findings
6. Grounding, hygiene, attack-graph enrichment, RL update, artifact persist

The pool is injectable via `pipeline.PoolCaller` for offline/stub tests.

### Dependencies

Approved third-party packages:

- `github.com/spf13/cobra` — CLI
- `golang.org/x/sync` — errgroup for parallel agents
- `mvdan.cc/sh/v3` — bash command parsing in `mcpbridge` (allowlist gate)

### Release build (embedded agents)

```bash
rsync -a agents_md/ neurosploit-go/internal/agents/agentsdata/
cd neurosploit-go && go build -tags embed_agents -o neurosploit ./cmd/neurosploit
```

Dev/test builds load `agents_md/` from disk (default, no build tag).

### Model Pool

`internal/pool.ModelPool` is a concurrency-capped pool of candidate models. It supports:

- API-key and subscription-CLI paths.
- Pause on token/quota exhaustion, resume via `/continue`.
- Cross-model voting for false-positive reduction.

The pool is injectable via the `pipeline.PoolClient` interface for offline tests.

## Testing Conventions

- Every package has `*_test.go` files with table-driven or scenario tests.
- Use `httptest` for HTTP-dependent packages (`creds`, `models`).
- Use a fake `PoolClient` in `cmd/neurosploit` for the `--offline` smoke test.
- Run `go test ./...` and `go vet ./...` before committing.

## Extending the LLM Layer

To add a new provider, edit `internal/models/models.go` `Providers()` and add a `Provider{}` entry with the OpenAI-compatible `base_url`, environment key name, and model list. The runtime picks it up automatically via `provider:model` syntax.
