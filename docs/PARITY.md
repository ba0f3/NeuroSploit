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
| `harness/src/models.rs` | `internal/models` | ✅ | 15 providers incl. Cursor CLI; HTTP/CLI chat. |
| `harness/src/pool.rs` | `internal/pool` | ✅ | Semaphore, failover, pause/resume, voting. |
| `harness/src/mcpbridge.rs` (design) | `internal/mcpbridge` | ✅ | Bash allowlist + `mvdan.cc/sh` parse; read/write/web. |
| `harness/src/report.rs` | `internal/report` | ✅ | HTML report for persist. |
| `harness/src/pipeline.rs` | `internal/pipeline` | ✅ | Run/Whitebox/Greybox/Host; recon→select→exploit→vote→chain. |
| `harness/src/rl.rs` | `internal/rl` | ✅ | Already implemented (existing). |
| `app/src/main.rs` | `cmd/neurosploit` | ✅ | Cobra subcommands; default entry starts REPL. |
| `app/src/repl.rs` | `internal/repl` | ✅ | liner REPL with tab completion, history, slash commands. |
| `app/src/tui.rs` | `internal/tui` | ✅ | bubbletea Mission Control TUI; stdio wizard helpers retained. |
| `agents_md/*.md` | `agents_md/*.md` | ✅ | Shared, unchanged. |

## Deviation Log

1. **Login function name**: `creds.login()` in Rust is `creds.DoLogin()` in Go because Go cannot have a type and function with the same name.
2. **ChatCLI streaming**: The Rust `models.rs` parses Claude `--output-format stream-json` events live. The Go port spawns the CLI synchronously and returns stdout; progress channel events are not yet parsed from stream-json.
3. **TUI**: Rust uses ratatui full-screen. Go uses bubbletea Mission Control (`neurosploit tui <url>`); stdio wizard helpers remain for non-terminal flows.
4. **REPL**: Go uses `peterh/liner` (line editing, tab completion, `.neurosploit/history`). Default `neurosploit` with no subcommand starts the REPL.
5. **CLI `--offline`**: Go stub mode runs the full pipeline with canned responses (self-test); Rust `cfg.offline` skips live exploitation.

## Verification

Run the full suite with:

```bash
cd neurosploit-go
go test ./... -timeout 30s
go vet ./...
```

All packages currently pass.
