# NeuroSploit Go — Phase 2 Design

- **Date:** 2026-06-30
- **Topic:** Close Rust parity gaps in `neurosploit-go/` after initial port
- **Status:** Approved (brainstorming complete)
- **Predecessor:** `docs/superpowers/plans/2026-06-30-neurosploit-go-port.md`

## Goal

Bring the Go harness to functional parity with Rust `pipeline.rs` orchestration: recon → LLM agent selection from `agents_md/` → parallel specialist exploitation with proper prompt substitution. Add Cursor CLI subscription support, Vietnamese hygiene calibration, bash MCP permission gating with proper shell parsing, and optional embedded `agents_md/` for single-binary release builds.

## Decisions (from brainstorming)

| Topic | Decision |
|---|---|
| Pipeline | Replace POMDP `Runner` with Rust-faithful `Run`/`RunWhitebox`/`RunGreybox`/`RunHost` |
| Vietnamese | Hygiene only — hedging words + exposure keywords in `hygiene.go` (EN/PT/VI trilingual) |
| `agents_md` embed | Build-tag split: disk load (dev default) vs `//go:embed` (release `-tags embed_agents`) |
| Bash MCP | Parse with `mvdan.cc/sh/v3/syntax`; persist allowlist to `.neurosploit/bash_allowlist.json`; prompt on first unseen command |
| Cursor provider | New `cursor` provider key; binary `agent` (fallback `cursor-agent`); non-interactive `-p --output-format text --trust` |
| Logging | Restore Rust-style progress lines; `-v` adds debug detail (recon snippets, per-agent launch) |
| Out of scope | REPL (`liner`), TUI (`bubbletea`), Rust backport of Cursor provider |

## Approach

**Approach A — Replace `Runner` with ported `Run()` (selected).**

Port `neurosploit-rs/crates/harness/src/pipeline.rs` as package-level functions with shared helpers (`selectAgents`, `exploitAgents`, `validate`, `chainRound`, `finish`). The current POMDP `Runner` loop is removed from the CLI path; `belief`/`pomdp` packages remain but are not wired into black-box `run`.

Alternatives rejected:
- **Incremental patch on `Runner`** — POMDP loop conflicts with Rust linear flow.
- **Hybrid POMDP outer shell** — unnecessary complexity.

---

## Section 1 — Pipeline orchestration

### Current gap

`internal/pipeline/pipeline.go` implements a POMDP belief loop with hardcoded `reconSystem()` / `exploitSystem()`. It does not call `agents.Load`, has no `TaskSelect`, does not substitute `{target}` / `{recon_json}` in agent prompts, and lacks validate/chain/persist.

### Target flow (black-box `Run`)

```
agents.Load(base)
  → recon (pool.Complete TaskRecon, RECON_SYS + operator directives)
  → selectAgents (pool.Complete TaskSelect, SELECT_SYS + catalog)
  → exploitAgents (errgroup, parallel, agent.System + renderUser(agent.User))
  → validate (N-model vote)
  → chainRound (chain agents on confirmed findings)
  → finish (grounding, hygiene, attackgraph, rl, persist artifacts)
```

### Public API

```go
type RunOutput struct {
    Target     string
    Findings   []types.Finding
    AgentsRan  []string
    Candidates int
    Recon      string
    Workdir    string
    Artifacts  []string
}

func Run(ctx context.Context, cfg types.RunConfig, lib agents.Library, pool PoolCaller, progress chan<- string) RunOutput
func RunWhitebox(ctx context.Context, cfg types.RunConfig, lib agents.Library, pool PoolCaller, progress chan<- string) RunOutput
func RunGreybox(ctx context.Context, cfg types.RunConfig, lib agents.Library, pool PoolCaller, progress chan<- string) RunOutput
func RunHost(ctx context.Context, cfg types.RunConfig, lib agents.Library, pool PoolCaller, progress chan<- string) RunOutput
```

`PoolCaller` interface (testable; matches existing `pool.ModelPool` method names):

```go
type PoolCaller interface {
    SetProgress(chan<- string)
    Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error)
    Vote(system, user string, n int, skip string) (confirmed, total int)
    StopExploiting() bool
}
```

Pipeline functions take `ctx context.Context` for cancellation/timeouts; pool methods honor cancellation via internal atomics (`Cancel`, `StopExploiting`).

### Prompt doctrine

Port constants verbatim from Rust `pipeline.rs`:
- `RECON_SYS`, `REACT_DOCTRINE`, `DEPTH_DOCTRINE`, `VOTE_SYS`, `CODE_VOTE_SYS`, `CHAIN_SYS`, `SELECT_SYS`, `HOST_TOOLING`, `HOST_RECON_SYS`
- `operatorDirectives(cfg)`, `toolDoctrine(mcpOn)`

### Prompt substitution

```go
func renderPrompt(tmpl string, vars map[string]string) string
```

Replace placeholders in agent `User`/`System` prompts:
- `{target}` — engagement target URL/path/host
- `{recon_json}` — capped recon blob (3500 runes for exploit, 3000 for select)
- `{scope}` — from cfg when set
- `{focus}` — from cfg.Instructions when set

Exploit user prompt assembly matches Rust:

```
AUTHORIZED engagement — … {target}. …
{directives}{react}{depth}{doctrine}{renderUser(ag.User)}
When done, reply with ONLY a JSON array of confirmed findings …
```

Exploit system prompt: `ag.System` (not hardcoded `exploitSystem()`).

### Agent selection

`selectAgents(pool, recon, focus, catalog, progress)`:
1. Build catalog list: `name — title [cwe]` per agent.
2. `pool.Complete("select", TaskSelect, SELECT_SYS, user)`.
3. Parse JSON array via `parseStringArray`.
4. Fallback: `heuristicSelect` (BASELINE list + keyword signals from Rust).
5. Dedup selected agents; cap at `cfg.MaxAgents`.

### Finding extraction

Port `extractFindings`, `dedupFindings`, `normSev`, lenient JSON coercion from Rust. Replace line-scanner `parseFindings`.

### Progress logging

Send on `progress chan<- string` (Rust `tx.send` parity):
- `Loaded N agents …`
- `recon complete via {model}`
- `intelligently selected N agent(s) matching recon: …`
- `exploit {name} via {model} → N candidate(s)`
- `finding: [sev] title @ endpoint`
- `N candidate finding(s) (deduped) — validating by N-model vote`

With `cfg.Verbose` / `-v`: additionally recon snippet (280 chars), `▶ launching agent: …`.

CLI wires progress to stdout (non-verbose = Rust default progress; verbose = extra debug).

### Artifacts (`persist`)

Write to `cfg.Workdir` (`runs/ns-<ts>-<target>/`):
- `recon.json`, `recon.md`, `exploitation.md`
- `findings.json`, `findings.md`
- `report.html` (via `internal/report`)
- `status.json` (`complete`)

RL state: `<base>/data/rl_state_go.json`.

### Offline mode

`cfg.Offline`: recon → `"{}"`, select agents (RL-ranked), skip live exploitation, persist empty findings. Matches Rust offline behavior.

---

## Section 2 — `agents_md` embed (build-tag split)

### Dev default (`!embed_agents`)

Current behavior unchanged: `agents.Load(base)` reads `<base>/agents_md/` via `filepath.WalkDir`. Tests walk up to repo root.

### Release (`-tags embed_agents`)

```
internal/agents/
  agents_load.go      //go:build !embed_agents
  agents_embed.go     //go:build embed_agents
  agentsdata/         // copied at release build from repo agents_md/
```

- `//go:embed agentsdata/**` embeds all `.md` files.
- `Load(_ string)` parses embedded FS; ignores `base` parameter.
- Release build step (Makefile or `go generate`):

```bash
rsync -a ../agents_md/ internal/agents/agentsdata/
go build -tags embed_agents -o neurosploit ./cmd/neurosploit
```

- CI/tests run without embed tag (disk load).

---

## Section 3 — Cursor provider

Add to `models.Providers()`:

```go
{Key: "cursor", Label: "Cursor Agent", Kind: "cli",
 Models: []string{"auto", "claude-4.6-opus-high", "gpt-5.3-codex", "gemini-3-flash"}}
```

Implementation in `models.go`:
- `CLIBinaryFor("cursor")` → probe `agent` on PATH, fallback `cursor-agent`.
- `ChatCLI`: spawn `agent -p --model {model} --output-format text --trust` with prompt on stdin (system + `\n\n` + user), 600s timeout.
- `MCPSupported("cursor")` → `true`.
- When `--mcp` + `--subscription` + cursor provider: pass MCP config path if supported by CLI flags.

Usage: `neurosploit run https://target --subscription --model cursor:auto`

Go-only; no Rust backport in this phase.

---

## Section 4 — Bash MCP permissions + shell parsing

### Parsing

Replace `strings.Fields` in `mcpbridge.handleBash` with `mvdan.cc/sh/v3/syntax`:

```go
prog, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
// Walk AST to collect base commands (first word of each simple command / pipeline segment)
```

- Reject dangerous patterns (existing regex list) before permission check.
- Execute via `exec.Command("sh", "-c", cmd)` to honor pipes/redirections.

### Permission model

Persist to `<cwd>/.neurosploit/bash_allowlist.json`:

```json
{
  "commands": ["curl", "nmap", "dig", "ffuf"],
  "trust_all": false
}
```

Decision flow per bash tool call:
1. Parse command → extract base command names.
2. If all bases ∈ allowlist → run.
3. If `trust_all` session flag set → run.
4. If TTY: prompt — **Allow once** | **Always allow `{cmd}`** (persist) | **Trust all this session** | **Deny**.
5. Non-TTY: deny unless whitelisted.

New dependency: `mvdan.cc/sh/v3` (add written note to `AGENTS.md`).

---

## Section 5 — Vietnamese hygiene

Extend `internal/hygiene/hygiene.go`:

**WEASEL additions (Vietnamese):**
`có thể `, `có lẽ`, `tiềm năng`, `khả năng`, `có khả năng`, `nếu như`, `trong trường hợp`, `dường như`, `có thể sẽ`

**ExposureKeywords additions (Vietnamese):**
`tiết lộ`, `lộ thông tin`, `phiên bản`, `cấu hình`, `thiếu bảo mật`, `banner`, `rò rỉ`, `phơi bày`

No CLI locale switch, no `agents_md` changes.

---

## Section 6 — CLI wiring (`cmd/neurosploit`)

Changes to `main.go`:
- `findBase()` → `agents.Load(base)` passed into `pipeline.Run`.
- Create `runs/ns-<ts>-<sanitized-target>/` workdir; set `cfg.Workdir`, `cfg.RLPath`.
- Progress channel: goroutine printing lines to stdout.
- Remove POMDP `pipeline.New(stub, reg, wm, cr)` path; use `pipeline.Run` returning `RunOutput`.
- `printFindings` + artifact paths on completion.
- Keep `-v` flag wired to `cfg.Verbose`.

Stub offline test updated to implement `PoolCaller` with canned recon JSON + finding JSON array.

---

## Section 7 — Explicitly out of scope

- REPL with `github.com/peterh/liner` — keep current stub.
- TUI with `bubbletea` — keep compile-only skeleton or stub.
- Rust backport of Cursor provider.
- Modifying `agents_md/` content.
- Modifying `neurosploit-rs/`.

---

## Dependency changes

| Package | Purpose | Approved? |
|---|---|---|
| `mvdan.cc/sh/v3` | Bash command parsing in mcpbridge | Yes (written note required) |

No other new dependencies.

---

## Testing

| Package | Test |
|---|---|
| `internal/pipeline` | Offline integration test with stub `PoolCaller`: recon `{}` → select → exploit returns JSON findings → validate → artifacts written |
| `internal/agents` | Embed tag test (build tag CI job optional); disk load test unchanged |
| `internal/mcpbridge` | Parse pipelines; allowlist persist; deny unlisted non-TTY |
| `internal/models` | Cursor binary probe (skip if not installed) |
| `internal/hygiene` | Vietnamese weasel word demotion test |

Gate: `cd neurosploit-go && go vet ./... && go test ./... && go build ./...`

---

## Implementation order

1. `agents` — embed build-tag + shared `renderPrompt`
2. `pipeline` — full Rust port (largest piece)
3. `cmd/neurosploit` — wire Load, progress, workdir
4. `models` — Cursor provider
5. `mcpbridge` — sh parse + allowlist
6. `hygiene` — Vietnamese terms
7. Update `docs/parity-rust-go.md` checklist

---

## File map (expected changes)

| File | Change |
|---|---|
| `internal/pipeline/pipeline.go` | Rewrite: Run/RunWhitebox/RunGreybox/RunHost |
| `internal/pipeline/pipeline_test.go` | Offline integration test rewrite |
| `internal/agents/agents_load.go` | Split from agents.go (`!embed_agents`) |
| `internal/agents/agents_embed.go` | New (`embed_agents`) |
| `internal/models/models.go` | Cursor provider + ChatCLI |
| `internal/mcpbridge/mcpbridge.go` | sh parse + permission gate |
| `internal/mcpbridge/allowlist.go` | New: load/save/prompt |
| `internal/hygiene/hygiene.go` | Vietnamese WEASEL/keywords |
| `internal/hygiene/hygiene_test.go` | Vietnamese test case |
| `cmd/neurosploit/main.go` | Wire pipeline.Run, progress, workdir |
| `AGENTS.md` | Note `mvdan.cc/sh/v3` dep + embed build tag |
| `docs/parity-rust-go.md` | Update pipeline row to ✅ after verify |
