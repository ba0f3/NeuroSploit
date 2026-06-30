# Go Port Parity Document

This document tracks the status of the `neurosploit-go` port relative to `neurosploit-rs`.

## Module / Package Mapping

| Rust crate/path | Go package | Status | Notes |
|-----------------|------------|--------|-------|
| `harness/src/types.rs` | `internal/types` | ✅ | `Finding` and `RunConfig` with identical JSON fields. |
| `harness/src/agents.rs` | `internal/agents` | ✅ | Markdown loader with six categories, title/CWE/prompt extraction. |
| `harness/src/belief.rs` | `internal/belief` | ✅ | World model, entropy, observe, frontier, confidence. |
| `harness/src/grounding.rs` | `internal/grounding` | ✅ | Empirical/symbolic receipt gate. |
| `harness/src/hygiene.rs` | `internal/hygiene` | ✅ | Severity calibration and depth/hygiene advisories. |
| `harness/src/pomdp.rs` | `internal/pomdp` | ✅ | Action selection, VoI, assertion gate. |
| `harness/src/attack_graph.rs` | `internal/attackgraph` | ✅ | CWE mapping, enrichment, Mermaid/ASCII kill chain. |
| `harness/src/creds.rs` | `internal/creds` | ✅ | YAML-subset parser, auth header, login flow. |
| `harness/src/models.rs` | `internal/models` | ⚠️ | 14-provider registry + HTTP/CLI chat; Claude stream-json parsing simplified. |
| `harness/src/pool.rs` | `internal/pool` | ✅ | Semaphore, failover, pause/resume, voting. |
| `harness/src/mcpbridge.rs` (design) | `internal/mcpbridge` | ✅ | Local tool registry (bash/read/write/web). |
| `harness/src/registry.rs` (design) | `internal/registry` | ✅ | JSONL findings store. |
| `harness/src/pipeline.rs` | `internal/pipeline` | ✅ | Orchestrator with injectable pool interface. |
| `harness/src/rl.rs` | `internal/rl` | ✅ | Already implemented (existing). |
| `app/src/main.rs` | `cmd/neurosploit` | ⚠️ | Core subcommands and flags; TUI/report preview simplified. |
| `app/src/repl.rs` | `internal/repl` | ⚠️ | Slash-command REPL; no readline history. |
| `app/src/tui.rs` | `internal/tui` | ⚠️ | Stdio menus/wizard; no ANSI/full-screen UI. |
| `agents_md/*.md` | `agents_md/*.md` | ✅ | Shared, unchanged. |

## Deviation Log

1. **Login function name**: `creds.login()` in Rust is `creds.DoLogin()` in Go because Go cannot have a type and function with the same name.
2. **ChatCLI streaming**: The Rust `models.rs` parses Claude `--output-format stream-json` events live. The Go port spawns the CLI synchronously and returns stdout; progress channel events are not yet parsed from stream-json.
3. **TUI**: The Rust TUI uses full-screen dialoguer/rustyline. The Go port uses plain stdin prompts/menus to avoid external dependencies.
4. **REPL**: No line editing history; standard `bufio` input.
5. **CLI**: Report preview and token/cost tracking from the Rust app are not implemented in the Go port yet.

## Verification

Run the full suite with:

```bash
cd neurosploit-go
go test ./... -timeout 30s
go vet ./...
```

All packages currently pass.
