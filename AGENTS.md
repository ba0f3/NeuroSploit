# NeuroSploit — OpenCode Agent Guide

## Repository layout

```
.
├── agents_md/              # Markdown agent library (shared by both harnesses)
├── neurosploit-rs/         # ↑ ORIGINAL Rust harness — reference/upstream only, DO NOT MODIFY
├── neurosploit-go/         # ← MAIN CODEBASE: Go port of the Rust version
├── docs/AGENTS.md          # Agent contributor guide (how to write .md agents)
├── .goreleaser.yaml        # GoReleaser config (root-level, builds neurosploit-go)
└── .github/workflows/
    ├── go-ci.yml           # Go vet + test + release build on push/PR
    ├── go-release.yml      # GoReleaser publish on v* tags
    └── release.yml         # Rust cross-platform release builds on v* tags
```

`neurosploit-rs/` is the original Rust codebase. Use it **for reference only** — read to understand architecture or check upstream behavior, but never modify. All active development is in `neurosploit-go/`.

## Go harness — key commands

Run from `neurosploit-go/` (or from the repo root — the binary auto-detects `agents_md/`):

```bash
go build ./cmd/neurosploit           # dev build (loads agents from disk)
go test ./... -timeout 30s           # all tests
go vet ./...                         # static analysis
make build-release                   # sync agents_md → embed + build with -tags embed_agents
make check                           # fmt → vet → test → build-release

# quick smoke test (no API keys needed)
./neurosploit run http://example.com --offline --max-agents 2 -v
./neurosploit models                 # list providers & models
```

The `Makefile` lives in `neurosploit-go/`. It syncs `agents_md/` from the repo root into `internal/agents/agentsdata/` for release builds.

## Agents: load path

- **Dev builds** (no tag): `Load()` reads `<base>/agents_md/` from disk. `findBase()` walks up from cwd looking for an `agents_md/` directory.
- **Release builds** (`-tags embed_agents`): agents are embedded via `//go:embed agentsdata/**/*`. The `base` argument is ignored.
- Always run dev builds from the repo root so `agents_md/` is found. Otherwise set `NEUROSPLOIT_BASE` or the binary prints an error.

## CI workflow (non-negotiable)

`go-ci.yml` runs on every push/PR touching `neurosploit-go/` or `agents_md/`:

1. `go vet ./...`
2. `go test ./... -timeout 30s`
3. `make build-release` (checks embedded build compiles)
4. `goreleaser check` (validates .goreleaser.yaml)

**Always run `go vet ./... && go test ./... -timeout 30s` before committing.** CI enforces it.

## Key architectural facts

| Fact | Detail |
|---|---|
| Entrypoint | `cmd/neurosploit/main.go` — cobra CLI |
| Orchestrator | `internal/pipeline/run.go` — recon → select → exploit → validate → chain → finish |
| Model routing | `internal/pool/pool.go` — failover on exhaustion, soft-stop on `/stop` |
| Providers | 14 providers in `internal/models/models.go` (`Providers()`). Add one there. |
| Agent load | `internal/agents/` — build-tag gated (`embed_agents` vs disk) |
| Shared structs | `internal/types/types.go` — `Finding`, `RunConfig` (JSON tags match Rust) |
| REPL | `internal/repl/repl.go` — liner-based, `.neurosploit/history` for history |
| TUI | `internal/tui/` — bubbletea Mission Control |
| Run output | `runs/ns-<ts>-<target>/` — findings.json, recon, transcripts |
| RL state | `data/rl_state_go.json` — agent weight updates |
| Offline mode | `--offline` flag uses stub pool, no API keys required |

## Subscription CLI gotchas

- Subscription models use dedicated provider keys: `claude`, `codex`, `agy`, `grok`, `cursor`/`agent`.
- API models use `anthropic`, `openai`, `gemini`, `openrouter`, etc. Mix both in one `--model` panel.
- Cursor/agent CLI concurrency is **capped at 1** (serial only).
- Other subscription CLIs cap at **3** concurrent sessions (independent of API concurrency).
- Non-stream timeout: 600s. Stream timeout: 900s.
- API HTTP client timeout: 120s.

## Testing conventions

- Every package should have `*_test.go` with table-driven or scenario tests.
- HTTP-dependent packages (`creds`, `models`) use `httptest`.
- Offline stub pool in `cmd/neurosploit/main_test.go` for smoke tests.
- Test files run from repo root so agents load from disk.

## Avoiding common mistakes

- **Don't edit files in `neurosploit-rs/`** — that's upstream reference only.
- **Don't run from inside `neurosploit-go/`** unless your cwd has a symlink to `agents_md/` — the binary walks up from cwd to find it. Run from repo root, or set `NEUROSPLOIT_BASE`.
- **Don't add new Go dependencies** without strong justification. The dependency list is intentionally minimal (cobra, liner, bubbletea, x/sync, mvdan.cc/sh).
- **Don't suppress type errors** (`as any`, `@ts-ignore`, `@ts-expect-error`) — this is Go, use proper error handling.
- **Don't add features to `internal/pipeline/prompt.go`** doctrine prompts without understanding the ReAct/Depth doctrines — they're carefully tuned for the LLM agents.
- **Don't manually sync agents** — `make build-release` / GoReleaser handles it. Dev builds read from disk automatically.

## When in doubt

Check the Rust source in `neurosploit-rs/` for reference architecture. The Go port mirrors its structure with `internal/` packages corresponding to `crates/` modules. See `docs/PARITY.md` for the deviation log.
