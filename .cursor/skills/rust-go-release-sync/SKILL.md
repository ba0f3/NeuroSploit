---
name: rust-go-release-sync
description: Syncs NeuroSploit upstream Rust release changes into neurosploit-go without regressing Go-only features. Use when porting a new upstream version (e.g. v3.5.3→v3.5.4), comparing JoasASantos/NeuroSploit releases, auditing Rust→Go parity, or when the user asks to sync/upstream/port Rust improvements to Go.
---

# Rust → Go Release Sync (NeuroSploit)

Port **behavior and contracts** from upstream Rust (`neurosploit-rs/`) into `neurosploit-go/`. Match upstream semantics; do **not** blindly copy Rust code or delete Go-only improvements.

## Hard rules

1. **Never modify `neurosploit-rs/`** in this repo — read-only reference. Upstream is [JoasASantos/NeuroSploit](https://github.com/JoasASantos/NeuroSploit).
2. **All active development** is in `neurosploit-go/`.
3. **Shared assets** (`agents_md/`, root docs) may update when upstream release includes them — but check Go-only agent metadata (`Tools`, `Skills`, `Output Schema`) still loads.
4. After every port: `cd neurosploit-go && go vet ./... && go test ./... -timeout 30s`.

## Go-only — do not remove or regress

Preserve these unless the user explicitly asks to drop them:

| Area | Packages / paths | Notes |
|------|------------------|-------|
| Tool recipes | `internal/tools`, `toolsdata/` | YAML executors, validation, dangerous-command guard |
| ReAct loop | `internal/toolloop` | Native `tool_calls` + `<tool_call>` fallback |
| Skills | `internal/skills`, `skills_md/` | Prompt injection |
| Playbooks | `internal/playbooks`, `playbooks/` | Phased runs via `--playbook` |
| Chain + tools | `internal/chainengine` + pipeline | Rust semantics + Go tool-loop on chain stages when `auto-tools` |
| Host recon tools | `pipeline` host path | Registry-backed recon (Rust is LLM-only) |
| Engagement layer | `internal/engagement`, `internal/source` | Shared CLI/REPL/TUI entry, git resolve |
| AI debug log | `internal/models/ailog.go`, `runs/*/ai.log` | Single append-only log per run |
| Offline stub | `--offline` | Go runs full pipeline with stub pool; Rust skips exploitation |
| Extra providers | `internal/models` | e.g. Cursor CLI — keep if already present |

Document intentional differences in [docs/PARITY.md](docs/PARITY.md) Deviation Log — do not “fix” them to match Rust unless upstream added equivalent behavior.

## Package mapping (Rust → Go)

Use [docs/PARITY.md](docs/PARITY.md) as source of truth. Quick map:

| Rust | Go |
|------|-----|
| `crates/harness/src/types.rs` | `internal/types` |
| `crates/harness/src/pipeline.rs` | `internal/pipeline` |
| `crates/harness/src/pool.rs` | `internal/pool` |
| `crates/harness/src/models.rs` | `internal/models` |
| `crates/harness/src/agents.rs` | `internal/agents` |
| `crates/harness/src/belief.rs` | `internal/belief` |
| `crates/harness/src/grounding.rs` | `internal/grounding` |
| `crates/harness/src/hygiene.rs` | `internal/hygiene` |
| `crates/harness/src/pomdp.rs` | `internal/pomdp` |
| `crates/harness/src/attack_graph.rs` | `internal/attackgraph` |
| `crates/harness/src/creds.rs` | `internal/creds` |
| `crates/harness/src/report.rs` | `internal/report` |
| `crates/harness/src/integrations.rs` | `internal/integrations` |
| `crates/harness/src/rl.rs` | `internal/rl` |
| `app/src/main.rs` | `cmd/neurosploit/main.go` |
| `app/src/repl.rs` | `internal/repl` |
| `app/src/tui.rs` | `internal/tui` |

Go-only packages (no Rust file): `tools`, `toolloop`, `skills`, `playbooks`, `chainengine`, `engagement`, `source`, `mcpbridge`.

## Workflow

Copy this checklist and track progress:

```
Release sync vX.Y.Z:
- [ ] 1. Identify upstream delta
- [ ] 2. Classify each change
- [ ] 3. Port harness behavior to Go
- [ ] 4. Wire CLI / types / tests
- [ ] 5. Update docs + PARITY.md
- [ ] 6. Verify CI commands
```

### Step 1 — Identify upstream delta

1. Read upstream `RELEASE.md` for the target version.
2. Compare tags on GitHub: `vOLD...vNEW` (commits + files changed).
3. Focus on paths under `neurosploit-rs/crates/harness/` and `neurosploit-rs/app/`.
4. Note shared changes: `agents_md/`, root `README.md`, `TUTORIAL.md`, `setup.sh`.

Ignore Rust-only release infra unless it affects shared docs.

### Step 2 — Classify each change

For every upstream commit/file, assign **one** category:

| Category | Action |
|----------|--------|
| **A — Harness logic** | Port to mapped Go package; mirror tests |
| **B — CLI flag / config** | Add to `types.RunConfig` + `cmd/neurosploit` flags + REPL if upstream has REPL support |
| **C — Prompt / constant** | Update `internal/pipeline/prompt.go` (or agent-facing strings) verbatim intent |
| **D — Shared agents** | Sync `agents_md/` only; no Go code unless loader breaks |
| **E — Docs / version** | Update `RELEASE.md`, `README.md`, `TUTORIAL.md` at repo root |
| **F — Go already ahead** | Skip port; ensure PARITY.md notes Go extension |
| **G — Rust-only / UI library** | Skip (ratatui vs bubbletea, Cargo, etc.) unless behavior contract changes |

If unsure, read Rust implementation **and** current Go equivalent side-by-side before editing.

### Step 3 — Port harness behavior

**Minimal diff principle:** change only lines traceable to upstream delta.

1. **`types.RunConfig` / `Finding`** — JSON field names must stay compatible with Rust (`json` tags).
2. **Pool / models** — port voting, verdict parsing, provider lists, timeouts together.
3. **Pipeline** — preserve stage order (recon → select → exploit → validate → chain → refute → finish). When Rust adds a stage, insert at the same point in Go modes (`Run`, `RunGreybox`, `RunHost`, `RunWhitebox`, `RunPlaybook` if applicable).
4. **Integrations** — port only what Go supports; extend `internal/integrations` incrementally.
5. **Do not** replace Go tool-loop paths with Rust’s inline shell-only doctrine.

When Rust replaces a function (e.g. `chain_round` → `attack_chain`), refactor the Go equivalent (`chainengine` / `runChainEngine`) to match **semantics**, not line count.

### Step 4 — Tests and CLI

- Add table-driven tests mirroring upstream `#[test]` cases (verdict parsing, quorum, dedup, chain rounds).
- Extend `pool_test.go`, `pipeline/*_test.go`, or package-specific tests — smallest test that fails if logic breaks.
- Wire new flags on **all** engagement commands upstream wires (`run`, `whitebox`, `greybox`, `host`, `tui`, `pr`, `watch` if Go has them).
- Run offline smoke: `./neurosploit run http://example.com --offline --max-agents 2 -v`

### Step 5 — Update docs

1. Prepend release notes to root `RELEASE.md`.
2. Bump version strings in `README.md`, `TUTORIAL.md`.
3. Update [docs/PARITY.md](docs/PARITY.md):
   - Module mapping notes
   - Deviation log (new or resolved items)
4. Do **not** edit the plan file if user attached one.

### Step 6 — Verify

```bash
cd neurosploit-go
go vet ./...
go test ./... -timeout 30s
make build-release   # if agents_md or embed changed
```

## Common upstream change patterns

| Upstream pattern | Go touch points |
|------------------|-----------------|
| New `RunConfig` field + `--flag` | `internal/types/types.go`, `cmd/neurosploit/main.go`, `engagement.Execute` |
| New pipeline stage | `internal/pipeline/run.go`, `whitebox.go`, `playbook_run.go` |
| Stronger validation | `internal/pool/verdict.go`, `pipeline/validate`, `refutePass` |
| Attack chaining | `internal/chainengine`, `runChainEngine`, `ExtractChain` |
| New provider/model | `internal/models/models.go` `Providers()` |
| Integration feature | `internal/integrations`, CLI subcommands |

## Anti-patterns

- Copy-pasting Rust into Go without idiomatic error handling.
- Deleting `internal/tools` or tool-loop calls to “match Rust simplicity”.
- Modifying `neurosploit-rs/` in this fork.
- Porting ratatui UI literally instead of equivalent bubbletea behavior.
- Large drive-by refactors unrelated to the release delta.
- Forgetting whitebox vs black-box mode differences (upstream often chains only on live modes).

## Output for the user

When finishing a sync, report:

1. **Upstream version** ported (e.g. v3.5.3 → v3.5.4)
2. **Behavior ported** (bullet list)
3. **Intentionally skipped** (Rust-only or already in Go)
4. **Go-only preserved** (confirm no regressions)
5. **Files changed** (grouped by package)
6. **Verification** (`go vet` / `go test` result)

## Reference

Full mapping and deviation history: [docs/PARITY.md](docs/PARITY.md)

Repository guide: [AGENTS.md](AGENTS.md)
