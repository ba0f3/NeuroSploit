# NeuroSploit — Go Port Design

- **Date:** 2026-06-30
- **Topic:** Port the NeuroSploit Rust harness (`neurosploit-rs/`) to Go; ship a clean `AGENTS.md` for AI coding agents.
- **Status:** Approved (brainstorming complete, ready for implementation planning)

## Goal

Port NeuroSploit v3.5.3 from Rust to Go, keeping full functional parity, a simple
1:1 package structure for easier review and audit, and every original capability.
Produce a clean `AGENTS.md` contributor guide so AI coding agents working in this
repo follow consistent rules.

## Decisions (from brainstorming)

1. **Scope & coexistence** — Full parity. The Go port lives in a new
   `neurosploit-go/` directory alongside `neurosploit-rs/`. Both are kept. They
   share the repo-root `agents_md/` (markdown agents) and `data/` (RL state).
   The exact agent count is runtime-derived (the loader counts files on disk; the
   README itself is inconsistent between 303 and 329), so the port must not
   hardcode the number.
2. **Structure & dependencies** — Standard Go layout (`cmd/` + `internal/`),
   lean dependencies: stdlib `net/http` plus `cobra` (CLI), `bubbletea` (TUI),
   `liner` (REPL), `survey` (prompts), and `golang.org/x/sync`
   (`errgroup` + `semaphore`). No YAML library — the creds parser stays
   hand-rolled (zero-dep audit story).
3. **AGENTS.md** — A repo contributor guide for AI coding agents (CLAUDE.md-style):
   build/test/lint commands, Go conventions, code structure map, dependency rules,
   forbidden actions, commit style. Not the pentest safety rules.
4. **Behavioral compatibility** — Faithful but idiomatic. Same subcommands and
   flags; same `runs/` artifact filenames and `.neurosploit/` session layout;
   **identical JSON schemas** (so artifacts are interchangeable with Rust).
   Human-facing output text may read naturally in Go.
5. **Testing & audit aids** — Full unit tests for all pure modules; an offline
   pipeline integration test; a Rust→Go parity checklist doc.

## Approach

**Approach A — mirror 1:1 into packages (selected).** One Go package per Rust
module, same names, same responsibilities. This is the most auditable mapping
(file ↔ file), keeps each unit small and focused, and is idiomatic standard Go.
Alternatives considered: domain-grouped fewer packages (blurs 1:1 audit trace),
single flat package (no encapsulation, not idiomatic, worse for audit).

## Section 1 — Architecture & Package Map

`neurosploit-go/` is a single Go module
(`github.com/JoasASantos/NeuroSploit/neurosploit-go`), Go 1.26. It locates the
repo-root `agents_md/` and `data/` at runtime with the same
`NEUROSPLOIT_BASE` / walk-up-to-`agents_md/` logic as Rust.

### Package map (one package per Rust module)

| Rust source | Go package | Responsibility |
|---|---|---|
| `app/src/main.rs` | `cmd/neurosploit` | `main()`, cobra CLI dispatch, engagement helpers, `applyCreds`, `findBase` |
| `app/src/repl.rs` | `internal/repl` | liner-based interactive REPL, session/run history, composer |
| `app/src/tui.rs` | `internal/tui` | bubbletea "Mission Control" TUI |
| `harness/src/types.rs` | `internal/types` | `Finding`, `RunConfig` (identical JSON schema) |
| `harness/src/agents.rs` | `internal/agents` | markdown agent library loader |
| `harness/src/models.rs` | `internal/models` | provider registry (12 providers), `ChatClient` (HTTP API + CLI-subscription subprocess) |
| `harness/src/pool.rs` | `internal/pool` | `ModelPool`: concurrency semaphore, failover, cancel/soft-stop/pause-resume, N-model vote |
| `harness/src/pipeline.rs` | `internal/pipeline` | orchestration: `Run`/`RunWhitebox`/`RunGreybox`/`RunHost`, recon, selection, validation, chaining, persist |
| `harness/src/belief.rs` | `internal/belief` | POMDP `WorldModel`, Bayesian update, entropy/frontier |
| `harness/src/pomdp.rs` | `internal/pomdp` | value-of-information `Decide`, anti-hallucination `MayAssert` |
| `harness/src/rl.rs` | `internal/rl` | RL reward store |
| `harness/src/grounding.rs` | `internal/grounding` | tool-receipt verification gate |
| `harness/src/hygiene.rs` | `internal/hygiene` | severity calibration, depth audit, hygiene consolidation |
| `harness/src/attack_graph.rs` | `internal/attackgraph` | CWE→OWASP/MITRE/kill-chain map, Mermaid graph, ASCII kill-chain |
| `harness/src/creds.rs` | `internal/creds` | dependency-free YAML-subset parser + login flow |
| `harness/src/integrations.rs` | `internal/integrations` | GitHub/GitLab/Jira (net/http) |
| `harness/src/report.rs` | `internal/report` | HTML report + Typst `.typ` generation + `typst` subprocess for PDF |
| `harness/src/lib.rs` | (none — Go has no facade lib root) | re-exports become normal imports |

### Dependency graph (fan-in to orchestrator)

```
cmd/neurosploit ──▶ repl, tui, pipeline, agents, models, pool, types, creds, integrations
pipeline ──▶ agents, pool, rl, types, report, grounding, hygiene, attackgraph, belief, pomdp, creds
report ──▶ types, attackgraph
pool ──▶ models
```

No import cycles: `types` is a leaf; pure-logic packages (`belief`, `pomdp`,
`rl`, `grounding`, `hygiene`, `attackgraph`) depend only on `types` (or nothing).

### Dependencies (go.mod)

- `github.com/spf13/cobra` — CLI (maps clap derive)
- `github.com/peterh/liner` — REPL line editing (maps rustyline)
- `github.com/charmbracelet/bubbletea` + `bubbles` + `lipgloss` — TUI (maps ratatui+crossterm)
- `github.com/AlecAivazis/survey/v2` — prompts (maps dialoguer)
- `golang.org/x/sync` — `errgroup` + `semaphore` (maps tokio Semaphore + stream concurrency)
- stdlib: `net/http`, `encoding/json`, `os/exec`, `regexp`, `embed`, `sync`, `context`, `time`, `path/filepath`

No YAML library — `creds.rs`'s hand-rolled YAML-subset parser is ported as-is.

### Concurrency model (tokio → Go)

| Rust | Go |
|---|---|
| `#[tokio::main]` + async fns | `main()` + goroutines (no async/await) |
| `tokio::sync::mpsc::Sender` | buffered `chan string` for progress events |
| `tokio::sync::Semaphore` | `golang.org/x/sync/semaphore.Weighted` |
| `tokio::sync::Notify` | a `chan struct{}` re-created per resume, or `sync.Cond` |
| `stream::iter().buffer_unordered(n)` | `errgroup.WithContext` + `g.SetLimit(n)` over agents |
| `tokio::process::Command` | `os/exec.Command` |
| `AtomicBool` cancel/soft/paused | `atomic.Bool` |
| `tokio::select!` cancel race | `ctx.Done()` + goroutine for hard-cancel |

Every blocking method takes a `context.Context` (first arg) for
cancellation/timeout, replacing Rust's manual cancel-flag polling.

## Section 2 — Components (per-package design)

### `internal/types`
`Finding` and `RunConfig` structs with JSON field names/tags identical to the
Rust `serde` schema (so `findings.json`, `recon.json`, `status.json` are
interchangeable). `Finding` keeps all 20 fields including `ChainsFrom []string`.
`DefaultFinding()` mirrors the Rust `Default` impl (`Severity:"Info"`, etc.).
`NewRunConfig(target)` constructor.

### `internal/agents`
`Agent{Name,Title,CWE,Kind,System,User}` and
`Library{Vulns,Meta,Recon,Code,Infra,Chains []Agent}`. `Load(base)` walks
`agents_md/{vulns,meta,recon,code,infra,chains}/*.md` with `filepath.WalkDir`
(depth 1) and applies the same 4 regexes (`# title`, `CWE-\d+`,
`## User Prompt`, `## System Prompt`). `System`/`User` use struct tag `-` (not
serialized). Sorted by name. `Total()` helper.

### `internal/models`
`Provider{Key,Label,BaseURL,EnvKey,Kind,Models}`, `Providers()` returns the same
12-entry registry (Anthropic, OpenAI, xAI, Gemini, NVIDIA NIM, DeepSeek, Mistral,
Qwen, Groq, Together, LiteLLM, OpenRouter) + Ollama special-case.
`ModelRef{Provider,Model}` with `Label()` and `ParseProvider("p:m")`. `ChatClient`
with two paths:
- **API path:** `net/http` POST to `{base}/chat/completions` with the OpenAI
  schema (`Authorization: Bearer`, JSON `messages`, optional `max_tokens`).
  Token/cost parsed from the response into global atomic counters.
- **Subscription path:** `os/exec` spawning `claude`/`codex`/`grok`/`gemini` with
  `-p`/`--print` + `--mcp-config` where supported, streaming the CLI's structured
  activity lines to the progress channel.
Plus `InstalledCLIBackends()`, `MCPSupported()`, `EnsurePlaywrightMCP()`,
`WriteMCPConfig()`, `binaryInPath()`.

### `internal/pool`
`ModelPool` holding the `ChatClient`, a `*semaphore.Weighted`, `Candidates`,
`Subscription`, `MCPConfig`, plus `cancel/soft/paused atomic.Bool`, a
`resume chan struct{}`, `fallback []ModelRef` (mutex-guarded), and a
`progress chan<- string`. Methods: `Complete`, `CompleteRouted` (reorder by
`Task` — fast models for recon/select), `One`, `Vote` (yes/no confirmation
counting, finder moved last), `isExhaustion` (same keyword list), `ParkExhausted`
(blocks on `resume` until `/continue`), `Cancel`/`StopExploiting`/`Pause`/
`ContinueWith`/`Resume`. Cancellation: `ctx.Err()` checked before/after each
model call; a hard-cancel watcher goroutine for in-flight calls.

### `internal/pipeline`
The orchestrator. `RunOutput{Target,Findings,AgentsRan,Candidates,Recon,Workdir,Artifacts}`.
Four entry points: `Run` (black-box), `RunWhitebox`, `RunGreybox`, `RunHost`.
Shared internal helpers: `recon`, `selectAgents` (recon-aware keyword match +
RL weights + `maxAgents`/`pinned`), `exploitAgents` (errgroup + SetLimit, each
→ `pool.CompleteRouted` → `extractFindings`), `validate` (N-model vote, demote
failures), `chainRound`, `finish` (enrich, grounding gate, hygiene, RL update +
save, persist, status.json). The same prompt-doctrine constants (`RECON_SYS`,
`VOTE_SYS`, `CODE_VOTE_SYS`, `REACT_DOCTRINE`, tool doctrine, operator
directives) are ported verbatim. `extractFindings` uses the same lenient
JSON-coercion logic (`s()`, `conf()`, `normSev()`, `dedupFindings()`).

### `internal/belief`
`Kind` (Host/Service/Vuln/Exploit/Credential), `Node{ID,Kind,Label,P,Obs}` with
`Entropy()` (Shannon, same `clamp(1e-6, 1-1e-6)`), `Edge`,
`WorldModel{Nodes,Edges,Deterministic}` with
`Add/Link/Observe/SetKnown/Uncertainty/Frontier/IsConfident`. Bayes odds-ratio
update identical.

### `internal/pomdp`
`Action` (Recon/Exploit/Stop), `Policy{ExploreEntropy,AssertMinP,AssertMaxEntropy}`
(defaults 0.6/0.7/0.4), `ValueOfInformation`, `exploitEV`, `Decide`, `MayAssert`.
Pure functions over `WorldModel`.

### `internal/rl`
`RlState{Weights,Runs}`, `Load/Weight/Update/Save`, `severityReward`. Constants
`ALPHA=0.3`, `WMIN=0.05`, `WMAX=1.0`.

### `internal/grounding`
`Grounded{OK,Kind,Reason}`, `looksEmpirical`/`looksSymbolic` (same marker lists +
heuristics), `Ground`, `Gate` (demote + retain).

### `internal/hygiene`
`Calibrate`, `DepthAudit`, `HygieneSummary` + the same WEASEL/exposure/class
heuristics and the existing Rust unit tests ported to Go.

### `internal/attackgraph`
`Enrich` (CWE→OWASP/MITRE/stage map, same `mapCwe`), `Mermaid`, `ASCIIKillchain`.
`STAGE_ORDER`, `exploitability`. The Typst template (`report.typ`) is copied from
the Rust tree into `neurosploit-go/internal/report/templates/report.typ` and
embedded via `//go:embed templates/report.typ` so the binary is self-contained.

### `internal/creds`
`Creds{JWT,Header,Cookie,Login,SSH,Win}`, dependency-free YAML-subset parser
(`Load`), `authHeader`, `hostInstruction`, `loginInstruction`, `Login(l)` (real
HTTP POST via net/http, no-redirect, Set-Cookie/bearer extraction). `unquote`.

### `internal/integrations`
`Integrations{Github,Gitlab,Jira}` with the same env-var-name-not-value secret
policy, `Load/Save`, `authedCloneURL`, `githubPRHeadSHA`, `jiraCard`,
`jiraCardsFor`, `statusLines`. net/http calls.

### `internal/report`
`HTML(target, findings)` (same severity sort, chips, Mermaid block, kill-chain
table, CSS), `TypstReport` (generate `report.typ` with embedded data +
`//go:embed` template, shell out to `typst compile` for PDF, fall back to `.typ`).
`sevRank`, `sevColor`, `esc`, `tq`.

### `internal/repl`
`Session` struct (models, subscription, mcp, voteN, maxAgents, target, repo, auth,
creds, instructions), `Run()` loop using `liner` for line editing + history file,
multi-select via `survey`, slash-commands (`/run`, `/status`, `/finding`,
`/results`, `/expand`, `/pause`, `/continue`, `/integrations`, `/agents`,
`/models`, `/report`, `/quit`), background-run streaming via the progress channel
into `RunLive`, `.neurosploit/` session/runs/active-run checkpoint persistence
(JSON, same schema), `projDir()`.

### `internal/tui`
bubbletea program: `Ui` model (target, phase, feed deque, live findings, targets,
token totals, composer input), `Init/Update/View`, the same phase-tracking
`ingest` from progress lines, the same `feedSpan` coloring, composer that answers
`summary`/`pause`/`errors` locally without stopping the runner. lipgloss layout.

## Section 3 — Data Flow, CLI Surface & Error Handling

### Engagement data flow (identical to Rust)

```
target ─▶ recon (curl/nmap via model+exec) ─▶ recon JSON
       ─▶ selectAgents (recon-aware keyword match + RL weights + maxAgents/pinned)
       ─▶ exploitAgents (errgroup + SetLimit(concurrency); each → pool.CompleteRouted → extractFindings)
       ─▶ dedupFindings ─▶ validate (N-model vote; demote unconfirmed)
       ─▶ chainRound (chain agents on confirmed findings) ─▶ validate again ─▶ dedup
       ─▶ attackgraph.Enrich (OWASP/MITRE/stage)
       ─▶ grounding.Gate (tool-receipt check; demote ungrounded)
       ─▶ hygiene.Calibrate (cap unproven High/Critical → Medium) + DepthAudit + HygieneSummary
       ─▶ rl.Update + Save
       ─▶ persist (runs/ns-<ts>-<target>/: status.json, recon.json/.md, exploitation.md,
                   findings.json/.md, report.html, report.typ, report.pdf)
       ─▶ RL reward update (data/rl_state_go.json)
```

Every phase streams tagged progress lines (`recon complete`, `selected N agent(s)`,
`exploit X via M → N candidate(s)`, `finding: [sev] title @ endpoint`,
`vote … confirmed`, `chain …`) over the progress channel — consumed by the CLI
verbose printer, the REPL `RunLive`, and the TUI `Ui.ingest`. Same line formats so
the REPL/TUI parsers port unchanged.

### CLI surface (cobra, faithful to clap)

`neurosploit` with optional subcommand (no args → REPL):

- `run <url> [--model p:m]... [--max-agents N] [--vote-n N] [--offline] [--subscription] [--mcp] [--creds FILE] [--focus TEXT] [--jira] [-v]`
- `whitebox <path> [--model]... [--max-agents N] [--vote-n N] [--subscription] [--mcp] [-v]`
- `greybox <path> --url <app> [--model]... [--vote-n N] [--subscription] [--mcp] [--creds] [--focus] [--max-agents N] [--jira] [-v]`
- `host <target> [--model]... [--creds FILE] [--focus] [--max-agents N] [--vote-n N] [--offline] [--subscription] [-v]`
- `pr <repo> <number> [--model]... [--vote-n N] [--subscription] [--comment] [--jira] [-v]`
- `watch <repo> [--branch main] [--interval 300] [--model]... [--subscription] [--jira] [-v]`
- `tui <url> [--model]... [--subscription] [--mcp] [-v]`
- `integrations [show|enable|disable] [github|gitlab|jira]`
- `agents` — library counts
- `models` — provider/model list

Same flag names, defaults, and `-v` shorthand. `--offline` exercises the full
pipeline with stubbed model responses (no API/CLI calls) — the basis of the
integration test.

### Run artifacts & session layout (identical paths/schemas)

- `runs/ns-<unix-ts>-<sanitized-target>/` — `status.json`, `recon.json`,
  `recon.md`, `exploitation.md`, `findings.json`, `findings.md`, `report.html`,
  `report.typ`, `report.pdf`
- `.neurosploit/` (project-local) — `session.json`, `runs.json`,
  `active_run.json`, `integrations.json`, `.mcp.json`
- `data/rl_state_go.json` (Go's own RL store; Rust uses `rl_state_rs.json` — both
  kept so the two don't clobber each other, matching "coexist")
- `neurosploit-go/internal/report/templates/report.typ` — the Typst template
  copied from the Rust tree and embedded via `//go:embed` so the binary is
  self-contained

### Error handling

- Errors flow as Go `error` values (`fmt.Errorf` with `%w` wrapping,
  `errors.Is`/`As` for matching). `isExhaustion` checks `err.Error()` for the same
  keyword list.
- Pipeline-level: a failing agent logs to the progress channel
  (`test X failed: …`) and contributes zero findings — never aborts the whole run.
  Validation failures demote, not crash.
- Model call failures: `Complete` tries each candidate in order; on exhaustion it
  `ParkExhausted` (pauses until `/continue`), on other errors it returns the last
  error.
- Cancellation: `ctx.Err()` short-circuits; hard-cancel drops in-flight calls;
  soft-stop skips new exploit agents but lets in-flight finish and validation
  still runs.
- Subprocess errors (curl/nmap/typst/npx/CLI subscriptions): captured stderr
  surfaced as a progress note; the run degrades gracefully (typst missing → leave
  `.typ`, npx missing → fall back to curl-only doctrine).
- No panics on malformed data: `extractFindings` lenient coercion
  (numbers/strings/bools), UTF-8-safe truncation by rune count (Go slices runes,
    never bytes — avoids the Rust `truncate` byte-slice bug class entirely).

## Section 4 — Testing, AGENTS.md & Deliverables

### Testing strategy (`_test.go` per package)

- **`internal/types`**: JSON round-trip — encode a `Finding`/`RunConfig`, decode,
  assert field equality (guards the interchangeable-schema requirement).
- **`internal/agents`**: point `Load` at the real repo-root `agents_md/`, assert
  `Total()` equals the number of `.md` files actually on disk (counted at test
  time, not hardcoded), and that a known agent (`sqli_error`) parses
  `Title`/`CWE`/`System`/`User` correctly.
- **`internal/belief`**: entropy at p=0.5 ≈ 1.0 and p≈0/1 ≈ 0; a positive
  `Observe` raises `p`; `SetKnown` collapses; `Frontier` returns diffuse nodes
  sorted by entropy.
- **`internal/pomdp`**: `Decide` returns `Recon` when a node is diffuse, `Exploit`
  when sharp+high-p, `Stop` when nothing remains; `MayAssert` rejects
  diffuse/low-p nodes.
- **`internal/rl`**: `Update` moves weight toward reward and clamps to
  `[0.05,1.0]`; `severityReward` mapping; `Load`/`Save` round-trip.
- **`internal/grounding`**: `Gate` keeps an empirical-evidence finding, demotes a
  paraphrase-only one; white-box symbolic match vs miss.
- **`internal/hygiene`**: the Rust tests ported (`unproven_high_is_capped`,
  `proven_high_is_kept`, `exposure_without_exploit_flagged`,
  `exposure_with_exploit_on_same_host_not_flagged`).
- **`internal/attackgraph`**: `Enrich` fills OWASP/MITRE/stage for a known CWE
  (e.g. CWE-89 → A03:2021-Injection/T1190/initial-access) without overwriting
  model-set values; `Mermaid` non-empty when findings present; `ASCIIKillchain`
  stages ordered.
- **`internal/creds`**: parse `creds.example.yaml` (jwt/header/cookie +
  `login:`/`ssh:`/`windows:` blocks); `authHeader` precedence; `unquote` of
  single/double quotes.
- **`internal/pipeline` (offline integration test)**: `Run` with `--offline`
  against a fixture URL — stubbed `ChatClient` returns canned recon + a canned
  finding JSON; assert the run produces `runs/ns-*/` with `status.json`→complete,
  `findings.json` non-empty, `report.html` contains the finding title, and RL
  state written. This is the end-to-end parity anchor.

### Parity checklist doc — `docs/parity-rust-go.md`

A table mapping each Rust module → Go package with: line counts, public-API
parity, test coverage status, and a "verified behavior matches" checkbox column.
Updated as the port progresses; the offline integration test is the gate for
"pipeline parity verified."

### `AGENTS.md` (repo root) — contributor guide for AI coding agents

A concise, CLAUDE.md-style instructions file covering:

- **Project**: what NeuroSploit is; the two harnesses (Rust `neurosploit-rs/`,
  Go `neurosploit-go/`) coexist and share `agents_md/` + `data/`.
- **Repo layout**: the package map (one line per package) + where
  agents/data/templates live.
- **Build & run (Go)**: `cd neurosploit-go && go build ./...`,
  `go run ./cmd/neurosploit run <url> --offline`, `go vet ./...`,
  `golangci-lint run`, `go test ./...`.
- **Go conventions**: standard layout (`cmd/`+`internal/`); `context.Context` as
  first arg on all blocking funcs; errors via `fmt.Errorf("...: %w", err)`; no
  panics on bad input (lenient coercion); rune-safe truncation; struct JSON tags
  must match the Rust `serde` schema exactly; one package = one concern.
- **Dependency rules**: stdlib first; only the 5 approved libs
  (cobra/bubbletea/liner/survey/x-sync); no YAML lib (creds parser is
  hand-rolled); new deps require a note on why.
- **Concurrency**: goroutines + channels + `semaphore.Weighted` + `errgroup`; no
  external async runtime; `ctx.Done()` for cancel.
- **Forbidden actions**: no destructive/DoS logic in agents; authorized-testing
  -only; never store secrets in config files (env-var names only); never break the
  Rust↔Go JSON schema parity; don't edit `agents_md/` from the Go port.
- **Commit style**: conventional commits; one package per commit where practical;
  keep the parity doc in sync.
- **Testing requirement**: every pure module lands with its `_test.go`; the
  offline integration test must stay green.

### Deliverables summary

1. `neurosploit-go/` — full Go module, 16 internal packages + `cmd/neurosploit`,
   ~5,900 lines ported 1:1.
2. Unit tests for all pure modules + offline pipeline integration test.
3. `docs/parity-rust-go.md` — Rust→Go parity checklist.
4. `AGENTS.md` (repo root) — AI coding-agent contributor guide.
5. `neurosploit-go/README.md` — short build/run/parity note (recommended).

### Out of scope (explicitly)

Modifying `neurosploit-rs/` or `agents_md/`; changing provider lists or agent
content; adding features not in the Rust version. The Go port is a faithful port,
not a rewrite-with-extras.
