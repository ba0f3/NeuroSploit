# Go Port Parity Document

This document tracks the status of the `neurosploit-go` port relative to `neurosploit-rs`.

## Module / Package Mapping

| Rust crate/path | Go package | Status | Notes |
|-----------------|------------|--------|-------|
| `harness/src/types.rs` | `internal/types` | ✅ | `Finding` and `RunConfig` with identical JSON fields (incl. `chain_depth`). |
| `harness/src/agents.rs` | `internal/agents` | ✅ | Markdown loader with six categories, title/CWE/prompt extraction. |
| `harness/src/belief.rs` | `internal/belief` | ✅ | World model, entropy, observe, frontier, confidence. |
| `harness/src/grounding.rs` | `internal/grounding` | ✅ | Empirical/symbolic receipt gate. |
| `harness/src/hygiene.rs` | `internal/hygiene` | ✅ | Severity calibration and depth/hygiene advisories. |
| `harness/src/pomdp.rs` | `internal/pomdp` | ✅ | Action selection, VoI, assertion gate. |
| `harness/src/attack_graph.rs` | `internal/attackgraph` | ✅ | CWE mapping, enrichment, Mermaid/ASCII kill chain. |
| `harness/src/creds.rs` | `internal/creds` | ✅ | YAML-subset parser, auth header, login flow, AWS/GCP/Azure cloud blocks. |
| `harness/src/models.rs` | `internal/models` | ✅ | 15 providers incl. Cursor CLI; HTTP/CLI chat. |
| `harness/src/pool.rs` | `internal/pool` | ✅ | Semaphore, failover, pause/resume, voting, `ParseVerdict`, `QuorumConfirmed`. |
| `harness/src/mcpbridge.rs` (design) | `internal/mcpbridge` | ✅ | Bash allowlist + `mvdan.cc/sh` parse; read/write/web. |
| `harness/src/report.rs` | `internal/report` | ✅ | HTML report for persist. |
| `harness/src/pipeline.rs` | `internal/pipeline` | ✅ | Run/Whitebox/Greybox/Host orchestration; recon→select→exploit→vote→chain. |
| `harness/src/integrations.rs` | `internal/integrations` | ✅ | Minimal: Load + AuthedCloneURL for private git clone (greybox/whitebox). |
| — | `internal/source` | ✅ | `Resolve` — local path or cached `git clone` under `repos/`. |
| — | `internal/engagement` | ✅ | `ApplyCreds`, `DetectMode`, `NormalizeURL`; shared CLI/REPL/TUI entry. |
| `harness/src/rl.rs` | `internal/rl` | ✅ | Already implemented (existing). |
| `app/src/main.rs` | `cmd/neurosploit` | ✅ | `run`, `whitebox`, `greybox`, `host`, `tui`, `agents`, `models`. |
| `app/src/repl.rs` | `internal/repl` | ✅ | Mode detection, `/creds`, `/chain`, `/agents list`, liner history. |
| `app/src/tui.rs` | `internal/tui` | ✅ | Mission Control; `--repo` enables greybox mode. |
| `agents_md/*.md` | `agents_md/*.md` | ✅ | Shared; incremental `Tools`/`Skills`/`Output Schema` metadata. |
| — | `internal/tools` | ✅ | YAML tool recipes (`toolsdata/`), executor, dangerous-command guard. |
| — | `internal/toolloop` | ✅ | ReAct loop; native `tool_calls` + `<tool_call>` fallback. |
| — | `internal/skills` | ✅ | `skills_md/` loader and prompt injection. |
| — | `internal/playbooks` | ✅ | YAML playbook engine with phased execution. |
| — | `internal/chainengine` | ✅ | v3.5.4 multi-round attack chaining with loot carry-forward and per-round validation. |

## Deviation Log

1. **Login function name**: `creds.login()` in Rust is `creds.DoLogin()` in Go because Go cannot have a type and function with the same name.
2. **ChatCLI streaming**: The Rust `models.rs` parses Claude `--output-format stream-json` events live. The Go port spawns the CLI synchronously and returns stdout; progress channel events are not yet parsed from stream-json.
3. **TUI**: Rust uses ratatui full-screen. Go uses bubbletea Mission Control (`neurosploit tui <url>`); stdio wizard helpers remain for non-terminal flows.
4. **REPL**: Go uses `peterh/liner` (line editing, tab completion, `.neurosploit/history`). Default `neurosploit` with no subcommand starts the REPL.
5. **CLI `--offline`**: Go stub mode runs the full pipeline with canned responses (self-test); Rust `cfg.offline` skips live exploitation.
6. **Tools/skills/playbooks**: Go-only extensions — `toolsdata/`, `skills_md/`, `playbooks/` with ReAct toolloop. Rust harness uses inline shell doctrine only.
7. **Chain engine**: Go mirrors Rust v3.5.4 `attack_chain` (multi-round, per-foothold pivots, loot carry-forward, validate each round). Go chain stages retain tool-loop integration when `auto-tools` is enabled.
8. **Host recon tool-loop**: Go `RunHost` uses the tools registry for recon when available; Rust uses LLM-only recon.
9. **REPL host mode**: Go routes to `host` when `/target` is a non-HTTP IP/hostname and `/creds` has ssh/windows blocks. Rust REPL documents this but only implements it via the `host` CLI subcommand.
10. **v3.5.5 cloud creds**: Go `ApplyCreds` exports cloud env vars and prepends `CloudInstruction()` like Rust; inline GCP JSON written to temp file. Go-only: `ValidatePanel` preflight and `ai.log` debug logging preserved.

## Greybox / Host parity checklist

| Capability | Status |
|---|---|
| `pipeline.RunGreybox` / `RunHost` | ✅ |
| CLI `greybox` / `host` subcommands | ✅ |
| `engagement.ApplyCreds` (host SSH/AD + cloud AWS/GCP/Azure + auto-login) | ✅ |
| `source.Resolve` (GitHub clone) | ✅ |
| REPL mode detection + `/creds` | ✅ |
| TUI `--repo` greybox | ✅ |
| Offline tests (`TestRunGreyboxOffline`, `TestRunHostOffline`) | ✅ |

Run the full suite with:

```bash
cd neurosploit-go
go test ./... -timeout 30s
go vet ./...
```

All packages currently pass.
