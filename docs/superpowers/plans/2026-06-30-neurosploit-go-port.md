# NeuroSploit Go Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port NeuroSploit v3.5.3 from Rust (`neurosploit-rs/`) to a new Go module (`neurosploit-go/`) with full functional parity, a 1:1 package mirror for auditability, and a clean `AGENTS.md` for AI coding agents.

**Architecture:** One Go package per Rust module (16 `internal/` packages + `cmd/neurosploit`). Leaf packages (`types`, `belief`, `pomdp`, `rl`, `grounding`, `hygiene`, `attackgraph`, `agents`, `creds`) have no/minimal deps; `models` → `pool` → `pipeline` fan in; `report`, `integrations`, `repl`, `tui` are top-level consumers. Concurrency: goroutines + channels + `golang.org/x/sync/semaphore` + `errgroup` (replaces tokio). External tools (curl/nmap/typst/npx/CLIs) unchanged via `os/exec`.

**Tech Stack:** Go 1.26; stdlib `net/http`, `encoding/json`, `os/exec`, `regexp`, `embed`, `context`; `github.com/spf13/cobra` (CLI), `github.com/peterh/liner` (REPL), `github.com/charmbracelet/bubbletea`+`bubbles`+`lipgloss` (TUI), `github.com/AlecAivazis/survey/v2` (prompts), `golang.org/x/sync` (errgroup+semaphore).

## Global Constraints

- **Go version:** 1.26. **Module path:** `github.com/JoasASantos/NeuroSploit/neurosploit-go`.
- **Layout:** standard Go — `cmd/neurosploit/` + `internal/<pkg>/`. One package = one Rust module. No import cycles.
- **JSON parity:** struct `json` tags MUST match the Rust `serde` field names exactly so artifacts are interchangeable. Do NOT use `omitempty` on `Finding`/`RunConfig` core fields — Rust `#[serde(default)]` always emits them.
- **Dependencies:** only cobra, liner, bubbletea+bubbles+lipgloss, survey, x/sync. No YAML library (creds parser hand-rolled). No new deps without a written note; add via `go get` in the first task that needs them.
- **Concurrency:** `context.Context` first arg on every blocking function; goroutines+channels; `semaphore.Weighted` for caps; `errgroup.WithContext`+`SetLimit` for parallel agents. No async/await.
- **Errors:** `fmt.Errorf("...: %w", err)`; `errors.Is`/`As`; no panics on malformed input; UTF-8-safe truncation by rune count (never byte-slice `s[:n]`).
- **Shared data:** Go reads repo-root `agents_md/` and `data/` at runtime (same `NEUROSPLOIT_BASE` / walk-up-to-`agents_md/` logic as Rust). Go writes its OWN RL state to `data/rl_state_go.json`.
- **Typst template:** copy `neurosploit-rs/templates/report.typ` to `neurosploit-go/internal/report/templates/report.typ`; embed via `//go:embed`.
- **Do NOT modify** `neurosploit-rs/` or `agents_md/`. Faithful port, not rewrite-with-extras.
- **Port source of truth:** the Rust file named in each task. Port behavior, names, tables, constants verbatim; the Go coder reads the Rust source and writes idiomatic Go matching it. (This plan describes WHAT to port and the exact test assertions; the coder writes the actual Go code.)
- **Testing:** every pure module lands with its `_test.go`; `go vet ./...` and `go test ./...` stay green.
- **Build/test:** `cd neurosploit-go && go build ./...`; `go vet ./...`; `go test ./...`; `go run ./cmd/neurosploit run http://example.test --offline`.

## File Structure

`cmd/neurosploit/main.go`; `internal/` packages: `types`, `agents`, `belief`, `pomdp`, `rl`, `grounding`, `hygiene`, `attackgraph`, `creds`, `models`, `pool`, `report` (with `templates/report.typ`), `integrations`, `pipeline`, `repl`, `tui` — each with `<pkg>.go` and (where applicable) `<pkg>_test.go`. Plus `AGENTS.md` (repo root, Task 18) and `docs/parity-rust-go.md` (Task 19).

**Build order (dependency order):** Task 1 types → 2 agents → 3 belief → 4 pomdp → 5 rl → 6 grounding → 7 hygiene → 8 attackgraph → 9 creds → 10 models → 11 pool → 12 report → 13 integrations → 14 pipeline → 15 cmd/CLI → 16 repl → 17 tui → 18 AGENTS.md → 19 parity doc. Each task produces an independently testable deliverable and ends with a commit.

---

## Task 1: Module scaffold + `internal/types`

**Files:** Create `neurosploit-go/go.mod`, `neurosploit-go/internal/types/types.go`, `neurosploit-go/internal/types/types_test.go`

**Interfaces:**
- Consumes: nothing (leaf).
- Produces: `types.Finding` (20 JSON fields), `types.RunConfig`, `types.DefaultFinding() Finding`, `types.NewRunConfig(target string) RunConfig`. Consumed by nearly every later package.

- [ ] **Step 1: Write the failing test** — In `types_test.go`: construct a `Finding` with all 20 fields set, `json.Marshal`+`Unmarshal` into a fresh `Finding`, assert equality; unmarshal the JSON into `map[string]json.RawMessage` and assert all 20 keys present, exactly: `id,agent,title,severity,cwe,cvss,endpoint,payload,evidence,impact,remediation,confidence,validated,votes,owasp,mitre,stage,exploitability,business_impact,chains_from`; assert `DefaultFinding()` has `Severity=="Info"`, `Confidence==0`, `Validated==false`; assert `NewRunConfig("http://t")` has `Target=="http://t"`, `VoteN==3`, `Concurrency==8`, `Models==["anthropic:claude-opus-4-8"]`, non-nil `Pinned`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/types/`. Expected: FAIL — no Go files / types undefined.
- [ ] **Step 3: Write minimal implementation** — Create `go.mod` (module `github.com/JoasASantos/NeuroSploit/neurosploit-go`, `go 1.26`). Create `types.go` porting `neurosploit-rs/crates/harness/src/types.rs`: `Finding` with all 20 fields and `json` tags matching the Rust serde field names (snake_case, incl. `business_impact` and `chains_from`), NO `omitempty` on any `Finding` field; `RunConfig` with `json` tags matching `types.rs`, optional Rust fields (`workdir`,`rl_path`,`instructions`,`auth`,`repo`) as `*string` with `omitempty`; `DefaultFinding()` → `Finding{Severity:"Info", ChainsFrom: []string{}}`; `NewRunConfig(target)` → Rust `RunConfig::new` defaults (`VoteN:3, Concurrency:8, Models:["anthropic:claude-opus-4-8"], Pinned: []string{}`).
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/go.mod neurosploit-go/internal/types/ && git commit -m "feat(go): scaffold go module and internal/types (Finding, RunConfig)"`

## Task 2: `internal/agents` — markdown library loader

**Files:** Create `neurosploit-go/internal/agents/agents.go`, `agents_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `agents.Agent{Name,Title,CWE,Kind,System,User string}`, `agents.Library{Vulns,Meta,Recon,Code,Infra,Chains []Agent}`, `agents.Load(base string) Library`, `(Library) Total() int`. Consumed by `pipeline`, `cmd`, `repl`.

- [ ] **Step 1: Write the failing test** — In `agents_test.go`: find repo root by walking up from the test dir until a dir containing `agents_md` exists; `Load(root)`; assert `lib.Total() > 0`; assert an agent in `lib.Vulns` with `Name=="sqli_error"`, `CWE=="CWE-89"`, `Title` containing "SQL", non-empty `System`/`User`. Count `.md` files under `agents_md/{vulns,meta,recon,code,infra,chains}` with `filepath.WalkDir` and assert `lib.Total() == count` (robust — do NOT hardcode a number).
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/agents/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `agents.go` porting `neurosploit-rs/crates/harness/src/agents.rs`: `Load(base)` calls `loadDir` for `vulns,meta,recon,code,infra,chains` with kinds `vuln,meta,recon,code,infra,chain`. `loadDir(dir, kind)` uses `filepath.WalkDir` depth-1 over `*.md` and four `regexp` patterns matching the Rust regexes: title `(?m)^#\s+(.+?)\s*$`, CWE `CWE-\d+`, user `(?s)##\s*User Prompt\s*\n(.*?)(?:\n##\s|\z)`, system `(?s)##\s*System Prompt\s*\n(.*?)(?:\n##\s|\z)`. `Name`=file stem, `Title`=first title match or `Name`, `CWE`=first CWE match or empty, `User`/`System`=trimmed captures or empty. Sort each slice by `Name`. `Total()` sums all six.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/agents/ && git commit -m "feat(go): add internal/agents markdown library loader"`

## Task 3: `internal/belief` — POMDP world model

**Files:** Create `neurosploit-go/internal/belief/belief.go`, `belief_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `belief.Kind` (int enum `KindHost,KindService,KindVuln,KindExploit,KindCredential`), `belief.Node{ID string; Kind Kind; Label string; P float64; Obs uint32}` + `(Node) Entropy() float64`, `belief.Edge{From,To string; P float64}`, `belief.WorldModel{Nodes map[string]Node; Edges []Edge; Deterministic bool}` + `Add/Link/Observe/SetKnown/Uncertainty/Frontier/IsConfident`. Consumed by `pomdp`, `pipeline`.

- [ ] **Step 1: Write the failing test** — In `belief_test.go`: assert `Node{P:0.5}.Entropy()` ≈ 1.0 (±1e-6) and `Node{P:0.001}.Entropy()` ≈ 0 (±0.01). `Add("x",KindVuln,"x",0.5)` then `Observe({Node:"x",Positive:true,Reliability:0.9})` → `P>0.5` and `Obs` incremented. `SetKnown("x",true)` → `P`≈0.98, `Obs+3`. `Frontier(0.5)` returns only nodes with entropy > 0.5 sorted desc. `IsConfident("x",0.7,0.4)` false while diffuse, true after `SetKnown("x",true)`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/belief/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `belief.go` porting `neurosploit-rs/crates/harness/src/belief.rs` line-for-line: `Entropy` = Shannon of Bernoulli with `P` clamped `[1e-6,1-1e-6]` (`-(p*log2(p)+(1-p)*log2(1-p))`). `Observe`: `r`=reliability clamped `[0.5+1e-6,1-1e-6]`; `priorOdds=p/(1-p)`; lr `r/(1-r)` if positive else `(1-r)/r`; `P=post/(1+post)`; `Obs++`. `SetKnown`: `P=0.98|0.02`, `Obs+=3`. `Uncertainty(kind)`: mean entropy over matching kind (or all), 1.0 if empty. `Frontier(thresh)`: entropy>thresh sorted desc. `IsConfident(id,minP,maxEnt)`: `P>=minP && Entropy()<=maxEnt`. `Add` seeds if absent; `Link` appends edge with `P` clamped `[0,1]`.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/belief/ && git commit -m "feat(go): add internal/belief POMDP world model"`

## Task 4: `internal/pomdp` — value-of-information + anti-hallucination

**Files:** Create `neurosploit-go/internal/pomdp/pomdp.go`, `pomdp_test.go`

**Interfaces:**
- Consumes: `belief.WorldModel`, `belief.Kind`.
- Produces: `pomdp.Action{Type string; Node string; V float64}` (`Type` `recon|exploit|stop`), `pomdp.Policy{ExploreEntropy,AssertMinP,AssertMaxEntropy float64}`, `pomdp.DefaultPolicy() Policy`, `pomdp.ValueOfInformation(wm *belief.WorldModel, nodeID string) float64`, `pomdp.Decide(wm *belief.WorldModel, pol Policy) Action`, `pomdp.MayAssert(wm *belief.WorldModel, nodeID string, pol Policy) error`. Consumed by `pipeline`.

- [ ] **Step 1: Write the failing test** — In `pomdp_test.go`: build a `WorldModel` with a diffuse `Vuln` node (`P=0.5`); `Decide` returns `Action{Type:"recon"}`. After `SetKnown("x",true)`, `Decide` returns `Action{Type:"exploit"}`. Empty `WorldModel`: `Decide` returns `Action{Type:"stop"}`. `MayAssert` on a diffuse node → error message contains "diffuse"; on a low-`P` node contains "too low"; on a confident node returns `nil`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/pomdp/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `pomdp.go` porting `neurosploit-rs/crates/harness/src/pomdp.rs`: `DefaultPolicy()` → `{ExploreEntropy:0.6,AssertMinP:0.7,AssertMaxEntropy:0.4}`. `ValueOfInformation` = node `Entropy()` × kind weight (`Exploit`/`Credential`=1.0, `Vuln`=0.8, `Service`=0.5, `Host`=0.4); 0 if node absent. `exploitEV` returns 0 if `Entropy() > AssertMaxEntropy`, else `P`. `Decide`: best recon node (max VoI) vs best exploit node (max EV over `Exploit`/`Vuln`/`Credential`); if `voi>=ev && voi>(1-ExploreEntropy)` → `Recon`; else if `ev>0` → `Exploit`; else `Stop`. `MayAssert`: absent node → "no belief…"; entropy above max → "diffuse…"; `P<min` → "too low…"; else `nil`.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/pomdp/ && git commit -m "feat(go): add internal/pomdp value-of-information planner"`

## Task 5: `internal/rl` — RL reward store

**Files:** Create `neurosploit-go/internal/rl/rl.go`, `rl_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `rl.State{Weights map[string]float64; Runs uint64}`, `(State) Load(path string) State`, `(State) Weight(agent string) float64`, `(State) Update(agent string, reward float64)`, `(State) Save(path string) error`, `rl.SeverityReward(sev string) float64`. Constants `Alpha=0.3, Wmin=0.05, Wmax=1.0`. Consumed by `pipeline`.

- [ ] **Step 1: Write the failing test** — In `rl_test.go`: from a default state, `Update("a",1.0)` repeatedly moves `Weight("a")` toward 1.0 and reaches exactly 1.0 (clamped) after enough iterations; `Update("a",-1.0)` reaches the 0.05 floor. Assert `SeverityReward` maps `Critical→1.0, High→0.7, Medium→0.4, Low→0.2, Info→0.05`. `Save` to a temp file then `Load` round-trips `Weights` and `Runs`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/rl/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `rl.go` porting `neurosploit-rs/crates/harness/src/rl.rs`: `Load` reads + `json.Unmarshal`s, returning a zero `State` (non-nil `Weights` map) on any error. `Weight` returns stored or 0.5. `Update` does `w = clamp(w + Alpha*(reward - w), Wmin, Wmax)` into `Weights[agent]` (default 0.5). `Save` does `os.MkdirAll(parent)` + `os.WriteFile` of `json.MarshalIndent`. `SeverityReward` switches as above.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/rl/ && git commit -m "feat(go): add internal/rl reinforcement-learning reward store"`

## Task 6: `internal/grounding` — tool-receipt verification gate

**Files:** Create `neurosploit-go/internal/grounding/grounding.go`, `grounding_test.go`

**Interfaces:**
- Consumes: `types.Finding`.
- Produces: `grounding.Result{OK bool; Kind string; Reason string}`, `grounding.Ground(f *types.Finding, context string, whitebox bool) Result`, `grounding.Gate(findings []types.Finding, context string, whitebox bool) ([]types.Finding, demoted int)`. Consumed by `pipeline`.

- [ ] **Step 1: Write the failing test** — In `grounding_test.go`: `Gate` on a finding with evidence `"HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html"` (≥24 chars, ≥2 markers) → kept, demoted=0. A finding with evidence `"the app might be vulnerable"` (paraphrase) → demoted=1 and not in result. White-box: finding `Endpoint:"main.go:42"` with context containing `"main.go"` → kept (symbolic); same finding with context lacking the file → demoted.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/grounding/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `grounding.go` porting `neurosploit-rs/crates/harness/src/grounding.rs`: `looksEmpirical` markers verbatim (`http/`,`status`,`200`,`301`,`302`,`401`,`403`,`500`,`set-cookie`,`location:`,`content-type`,`<html`,`<script`,`server:`,`x-`,`alert(`,`uid=`,`root:`,`sql`,`error`,`stack`,`callback`,`oob`,`collaborator`,`$ `,`# `,`curl`,`nmap`); OK if `len(evidence)>=24` AND ≥2 markers match (case-insensitive). `looksSymbolic`: endpoint `file:line` whose basename appears in context, OR ≥2 tokens (len>4) of the evidence's first 6 words appear in context. `Ground`: whitebox+context → symbolic/missing; else empirical/missing. `Gate`: for each finding `Ground`; if !OK set `Validated=false`, append ` · receipt_missing` to `Votes`, demoted++; retain only `Validated`.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/grounding/ && git commit -m "feat(go): add internal/grounding tool-receipt verification gate"`

## Task 7: `internal/hygiene` — severity calibration, depth, consolidation

**Files:** Create `neurosploit-go/internal/hygiene/hygiene.go`, `hygiene_test.go`

**Interfaces:**
- Consumes: `types.Finding`.
- Produces: `hygiene.Calibrate(*[]types.Finding) []string`, `hygiene.DepthAudit([]types.Finding) []string`, `hygiene.HygieneSummary([]types.Finding) []string`. Consumed by `pipeline`.

- [ ] **Step 1: Write the failing test** — In `hygiene_test.go`, port the 4 Rust tests from `neurosploit-rs/crates/harness/src/hygiene.rs:146-186` verbatim as Go tests: (1) `Calibrate` on `[Flooding DoS, High, CWE-770, "https://a/x", "could overload", ""]` → severity "Medium", notes len 1; (2) `[SQLi, High, CWE-89, "https://a/x", "id=1' UNION SELECT version()-- returned 8.0.32 in the response body, proving injection", "1' OR '1'='1"]` → stays "High", notes len 0; (3) `DepthAudit` on `["Information Disclosure - .git exposed", Low, CWE-527, "https://a/.git", "leaked", ""]` → len 1; (4) two findings (banner exposure Low CWE-200 "Server: IIS" + SQLi High CWE-89 "1'--" same host) → `DepthAudit` len 0.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/hygiene/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `hygiene.go` porting `neurosploit-rs/crates/harness/src/hygiene.rs`: `hostOf` (strip scheme, before `/` and `?`, lowercase), `sevRank` (crit4/high3/med2/low1/else0), `WEASEL` list verbatim (English+Portuguese), `isExposure` (CWE contains one of `200,527,538,942,497,209,548,16` OR title keywords), `looksUnproven` ((hedged OR evidence<40 chars) AND empty payload), `classOf` (header→missing-security-headers, clickjack/frame→clickjacking, hsts→missing-hsts, etc.). `Calibrate`: High/Critical unproven → severity "Medium", append "(potential — impact not demonstrated)" if absent, push note. `DepthAudit`: exposures on hosts with no non-exposure finding sev≥Medium → flag, truncate 8. `HygieneSummary`: group exposures by class, >1 host → advise consolidate.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/hygiene/ && git commit -m "feat(go): add internal/hygiene severity calibration and depth audit"`

## Task 8: `internal/attackgraph` — CWE→OWASP/MITRE/kill-chain, Mermaid, ASCII

**Files:** Create `neurosploit-go/internal/attackgraph/attackgraph.go`, `attackgraph_test.go`

**Interfaces:**
- Consumes: `types.Finding`.
- Produces: `attackgraph.Enrich(*[]types.Finding)`, `attackgraph.Mermaid([]types.Finding) string`, `attackgraph.ASCIIKillchain([]types.Finding) string`. Consumed by `pipeline`, `report`.

- [ ] **Step 1: Write the failing test** — In `attackgraph_test.go`: `Enrich` on `Finding{CWE:"CWE-89"}` with empty OWASP/MITRE/stage → sets `OWASP="A03:2021-Injection"`, `MITRE="T1190"`, `Stage="initial-access"`, `Exploitability` derived (conf≥0.85→trivial). `Enrich` does NOT overwrite a preset `OWASP="custom"`. `Mermaid` on a non-empty findings slice contains `"flowchart LR"` and `"subgraph"`. `Mermaid([])` returns `""`. `ASCIIKillchain` lists stages in `STAGE_ORDER` order.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/attackgraph/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `attackgraph.go` porting `neurosploit-rs/crates/harness/src/attack_graph.rs`: `mapCwe` as a Go `switch` on the numeric CWE — copy ALL rows verbatim from `attack_graph.rs:13-33` (e.g. `89|943 → ("A03:2021-Injection","T1190","initial-access")`, `77|78|94|95|917|1336 → ("A03:2021-Injection","T1059","execution")`, `79|80 → ("A03:2021-Injection","T1059.007","execution")`, …, default `("A04:2021-Insecure-Design","T1190","initial-access")`). `STAGE_ORDER=["recon","initial-access","execution","credential-access","privesc","lateral","exfil","impact"]`. `exploitability`: conf≥0.85→"trivial"; sev Critical/High→"moderate"; else "hard". `Enrich`: fill empties (don't overwrite); `BusinessImpact←Impact` if empty. `Mermaid`: `flowchart LR`, group by `stageRank`, `subgraph S<rank>["<stage>"]`, nodes `n<sanitized_id>["<title><br/>sev · owasp"]`, explicit `chains_from` edges `-->`, implicit stage progression `-.->` if no explicit edges. `ASCIIKillchain`: `▸ <stage padded 16> [sev] title (mitre)`.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/attackgraph/ && git commit -m "feat(go): add internal/attackgraph kill-chain mapping and Mermaid graph"`

## Task 9: `internal/creds` — hand-rolled YAML-subset parser + login flow

**Files:** Create `neurosploit-go/internal/creds/creds.go`, `creds_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `creds.Login`, `creds.SSH`, `creds.Win`, `creds.Creds{JWT,Header,Cookie *string; Login *Login; SSH *SSH; Win *Win}`, `creds.Load(path string) *Creds`, `(Creds) AuthHeader() *string`, `(Creds) HostInstruction() *string`, `(Creds) LoginInstruction() *string`, `creds.Login(ctx context.Context, l *Login) (authHeader, note string, err error)`, `creds.Unquote(s string) string`. Consumed by `pipeline`, `cmd`.

- [ ] **Step 1: Write the failing test** — In `creds_test.go`: write a temp `creds.yaml` with `jwt: eyJ...`, `header: "X-Api-Key: abc"`, a `login:` block (`url`,`method: POST`,`username_field`,`password_field`,`username`,`password`,`success`), an `ssh:` block and a `windows:` block. `Load` returns non-nil with `JWT` set, `Login.Method=="POST"`, `SSH.Port=="22"`, `Win` set. `AuthHeader()` returns `"Authorization: Bearer eyJ..."` (jwt precedence). `Unquote(`"x"`)=="x"`, `Unquote('y')=="y"`, `Unquote(z)=="z"`. Sub-test the network call with `httptest.Server`: POST returning `Set-Cookie` → `Login` returns `"Cookie: ..."`; a JSON body `{"access_token":"tok"}` → returns `"Authorization: Bearer tok"`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/creds/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `creds.go` porting `neurosploit-rs/crates/harness/src/creds.rs` line-for-line: dependency-free YAML-subset parser — strip `#` comments, skip blanks, detect indentation (space/tab), split on first `:`, empty-value non-indented header enters a block (`login`/`ssh`/`windows`/`win`/`ad`), indented lines populate the current block (`Login` default `Method:"POST"`, `SSH` default `Port:"22"`). `AuthHeader`: header→jwt→cookie precedence. `HostInstruction`: format SSH/Win creds directive. `LoginInstruction`: format the login-flow directive string. `Login(ctx,l)`: `net/http` client with `CheckRedirect` returning `http.ErrUseLastResponse` (no redirect), 30s timeout; POST/GET the form; collect first `Set-Cookie` pair; parse JSON body for `access_token`/`token`/`jwt`/`id_token`/`accessToken` → bearer; else join cookies → `Cookie:`. `Unquote`: strip surrounding matching quotes.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/creds/ && git commit -m "feat(go): add internal/creds yaml-subset parser and login flow"`

## Task 10: `internal/models` — provider registry + ChatClient

**Files:** Create `neurosploit-go/internal/models/models.go`, `models_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `models.Provider{Key,Label,BaseURL,EnvKey,Kind string; Models []string}`, `models.Providers() []Provider`, `models.ProviderFor(key string) (Provider, bool)`, `models.ModelRef{Provider,Model string}` + `Parse(s string) ModelRef` + `Label() string`, `models.ChatClient` with `Chat(ctx, m, system, user) (string, error)` (HTTP API) and `ChatCLI(ctx, label, provider, model, system, user, mcpConfig *string, progress chan<- string) (string, error)` (subscription subprocess), `models.CLIBinaryFor(provider) string`, `models.InstalledCLIBackends() []string`, `models.MCPSupported(provider) bool`, `models.EnsurePlaywrightMCP() error`, `models.WriteMCPConfig(dir, extra) (string, error)`, `models.BinaryInPath(name) bool`. Consumed by `pool`, `cmd`, `repl`.

- [ ] **Step 1: Write the failing test** — In `models_test.go`: `Providers()` returns ≥14 entries; assert `anthropic` present with `EnvKey=="ANTHROPIC_API_KEY"` and `Kind=="cli"`; `ollama` present with `Kind=="api"`. `ModelRef.Parse("anthropic:claude").Label()=="anthropic:claude"`; `ModelRef.Parse("bareword").Provider=="anthropic"`. `ProviderFor("ollama")` returns true; `ProviderFor("nope")` returns false. `MCPSupported("anthropic")==true`, `MCPSupported("gemini")==false`. `BinaryInPath("definitely_not_a_real_binary_xyz")==false`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/models/`. Expected: FAIL — undefined. Add `golang.org/x/sync` to go.mod via `go get golang.org/x/sync` if not present.
- [ ] **Step 3: Write minimal implementation** — Create `models.go` porting `neurosploit-rs/crates/harness/src/models.rs`: `Providers()` returns the full 14-entry registry copied verbatim from `models.rs:23-60` (anthropic, openai, xai, gemini, nvidia_nim, deepseek, mistral, qwen, groq, together, litellm, openrouter, azure, ollama) with exact `base_url`/`env_key`/`kind`/`models` values. `ModelRef.Parse` splits on first `:` (default provider "anthropic"). `ChatClient.Chat`: `net/http` 120s-timeout client; resolve key (gemini alias `GOOGLE_API_KEY`); Azure uses `AZURE_OPENAI_ENDPOINT`+`api-version`+`api-key` header, others Bearer; LiteLLM/Ollama honor `LITELLM_BASE_URL`/`OLLAMA_BASE_URL` overrides; POST `{base}/chat/completions` with JSON `{"model", "max_tokens":4096, "temperature":0.2, "messages":[{system},{user}]}`; parse `choices[0].message.content`. `ChatCLI`: `os/exec` spawning `claude`/`codex`/`grok`/`gemini` (claude streams structured events to progress; others prompt on stdin, 600s timeout via `context.WithTimeout`), per `models.rs:170-260`. `EnsurePlaywrightMCP` shells out to `npx -y @playwright/mcp@latest --help`. `WriteMCPConfig` writes `.mcp.json` with a `playwright` server + merges extra servers. `CLIBinaryFor` maps anthropic→claude, openai→codex, xai→grok, gemini→gemini.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/models/ neurosploit-go/go.mod neurosploit-go/go.sum && git commit -m "feat(go): add internal/models provider registry and ChatClient"`

## Task 11: `internal/pool` — ModelPool (concurrency, failover, cancel/pause, vote)

**Files:** Create `neurosploit-go/internal/pool/pool.go`, `pool_test.go`

**Interfaces:**
- Consumes: `models.ChatClient`, `models.ModelRef`, `golang.org/x/sync/semaphore`.
- Produces: `pool.Task` (int enum `TaskRecon,TaskSelect,TaskExploit,TaskValidate,TaskDefault`), `pool.ModelPool` with `New`/`WithAuth(models []ModelRef, concurrency int, subscription bool, mcpConfig *string) *ModelPool`, `(p) SetProgress(chan<- string)`, `(p) Complete(ctx, task Task, system, user) (ModelRef, string, error)`, `(p) CompleteRouted(ctx, task, system, user) (ModelRef, string, error)`, `(p) One(label, m, system, user) (string, error)`, `(p) Vote(ctx, system, user string, n int, skip string) (confirmed, total int)`, `(p) Route(task) []ModelRef`, `(p) Cancel()`, `(p) StopExploiting() bool`, `(p) Pause()`, `(p) ContinueWith(ModelRef)`, `(p) Resume()`, `pool.IsExhaustion(err) bool`. Consumed by `pipeline`, `cmd`.

- [ ] **Step 1: Write the failing test** — In `pool_test.go`: `IsExhaustion` on an error `"HTTP 429 rate limit exceeded"` → true; on `"network timeout"` → false. Define a small `caller` interface (`Complete(ctx, m, system, user) (string, error)`) so the test injects a fake: with a fake that always returns `"yes confirmed"`, `Vote` over a 3-model panel returns `(3,3)`; with a fake returning `"rejected"` returns `(0,3)`. `Route(TaskRecon)` puts a model whose name contains "haiku" before "opus".
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/pool/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `pool.go` porting `neurosploit-rs/crates/harness/src/pool.rs`: `ModelPool` holds `ChatClient` (or a `caller` interface for testability), `*semaphore.Weighted`, `Candidates []ModelRef`, `Subscription bool`, `MCPConfig *string`, `progress chan<- string`, `cancel/soft/paused atomic.Bool`, `resume chan struct{}`, `fallback []ModelRef` (mutex-guarded). `WithAuth` clamps concurrency to `[1,3]` when subscription. `IsExhaustion` keyword list verbatim from `pool.rs:13-20` (`rate limit`,`rate_limit`,`ratelimit`,`429`,`too many requests`,`quota`,`insufficient_quota`,`insufficient quota`,`out of credit`,`credit balance`,`billing`,`exhausted`,`overloaded`,`capacity`,`usage limit`,`resource_exhausted`,`resource exhausted`). `Complete` routes candidates, tries each in order, on exhaustion calls `ParkExhausted` (blocks on `resume` channel) then retries with fallbacks prepended, else returns last error. `Vote` reorders so the finder (`skip`) is last, takes `n` models, counts a yes/confirmed reply (`"verdict": "confirmed"`, starts with "yes", `confirmed: true`, `is_real": true`). `Route(TaskRecon|TaskSelect)` sorts fast models first (`haiku,flash,fast,mini,lite,chat,small`). `Cancel/StopExploiting/Pause/ContinueWith/Resume` flip the atomics / send on `resume`. Honor `ctx.Err()` before/after each model call.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/pool/ && git commit -m "feat(go): add internal/pool ModelPool (concurrency, failover, vote)"`

## Task 12: `internal/report` — HTML + Typst report

**Files:** Create `neurosploit-go/internal/report/report.go`, `report_test.go`; (template already copied to `neurosploit-go/internal/report/templates/report.typ`)

**Interfaces:**
- Consumes: `types.Finding`, `attackgraph.Mermaid`.
- Produces: `report.HTML(target string, findings []types.Finding) string`, `report.TypstReport(target string, findings []types.Finding, dir string) (string, error)`. Consumed by `pipeline`, `cmd`, `repl`.

- [ ] **Step 1: Write the failing test** — In `report_test.go`: `HTML` on one `Finding{Title:"SQLi", Severity:"Critical", Agent:"sqli", Endpoint:"/x"}` contains the title "SQLi", the string "NeuroSploit", and a severity chip. `HTML` on an empty findings slice contains "No validated findings". `tq("a\"b\\c")` produces a quoted Typst literal with the `"` and `\` escaped (no raw newline). (TypstReport is exercised by the pipeline integration test in Task 14; here just assert it writes a `report.typ` file to a temp dir.)
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/report/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `report.go` porting `neurosploit-rs/crates/harness/src/report.rs`: `//go:embed templates/report.typ` for the template. `sevRank` (Critical0/High1/Medium2/Low3/else4), `sevColor` (#c0392b/#e67e22/#f1c40f/#3498db/#7f8c8d), `esc` (HTML-escape `&<>`). `HTML(target, findings)`: sort by sevRank, build severity chips, a per-finding `<section>` (sev chip, title, meta line, payload/evidence `<pre>`, impact/remediation), an attack-path block with `attackgraph.Mermaid(sorted)` + a kill-chain table, the same dark CSS, footer — match the Rust format string in `report.rs:33-104`. `TypstReport`: build the `#let meta=…`/`#let findings=(…)` data lines (`tq` escapes `\`,`"`,newlines→space), prepend to the embedded template, write `report.typ`; if a `typst` binary is on PATH run `typst compile report.typ report.pdf` and return the pdf path, else return the `.typ` path.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/report/ && git commit -m "feat(go): add internal/report HTML and Typst report generation"`

## Task 13: `internal/integrations` — GitHub / GitLab / Jira

**Files:** Create `neurosploit-go/internal/integrations/integrations.go`, `integrations_test.go`

**Interfaces:**
- Consumes: `types.Finding`, `net/http`.
- Produces: `integrations.GithubCfg`, `GitlabCfg`, `JiraCfg`, `Integrations{Github,Gitlab,Jira}`, `(Integrations) Load(dir string) Integrations`, `(Integrations) Save(dir string) error`, `(Integrations) AuthedCloneURL(url string) string`, `(Integrations) GithubPRHeadSHA(ctx, ownerRepo string, number uint64) (string, error)`, `(Integrations) JiraCard(ctx, summary, description string) (string, error)`, `(Integrations) JiraCardsFor(ctx, target string, findings []types.Finding) (keys, errs []string)`, `(Integrations) StatusLines() []string`. Consumed by `pipeline`, `cmd`, `repl`.

- [ ] **Step 1: Write the failing test** — In `integrations_test.go`: `Load` on a nonexistent temp dir returns defaults — `Github.Enabled==false`, `Github.TokenEnv=="GITHUB_TOKEN"`, `Github.API=="https://api.github.com"`, `Gitlab.TokenEnv=="GITLAB_TOKEN"`, `Jira.IssueType=="Bug"`. `AuthedCloneURL("https://github.com/o/r")` is a no-op (returns the same URL) when GitHub is disabled. `StatusLines()` returns a slice of length 3 (github/gitlab/jira lines). (Network methods tested via `httptest.Server` sub-tests: `JiraCard` against a stub returning `{"key":"SEC-1"}` returns `"SEC-1"`.)
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/integrations/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `integrations.go` porting `neurosploit-rs/crates/harness/src/integrations.rs`: the three cfg structs + `Integrations` with the same defaults; **secrets are env-var names, not values** (read the env var at call time). `Load`/`Save` to `<dir>/integrations.json`. `AuthedCloneURL`: if GitHub enabled + URL starts `https://github.com/` + token present → `https://x-access-token:<tok>@github.com/<rest>`; same for GitLab. `GithubPRHeadSHA`: clone + `git rev-parse`. `JiraCard`: basic-auth (email+token) POST to `<base>/rest/api/2/issue`, parse `key`. `JiraCardsFor`: loop findings, format summary/description per the Rust template, collect keys/errs. `StatusLines`: the 3 badge lines.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/integrations/ && git commit -m "feat(go): add internal/integrations (GitHub/GitLab/Jira)"`

## Task 14: `internal/pipeline` — orchestrator (black/white/grey/host) + offline integration test

**Files:** Create `neurosploit-go/internal/pipeline/pipeline.go`, `pipeline_test.go`

**Interfaces:**
- Consumes: `agents.Library`, `pool.ModelPool`/`pool.Task`, `rl.State`, `types.Finding`/`RunConfig`, `report`, `grounding`, `hygiene`, `attackgraph`, `belief`, `creds`.
- Produces: `pipeline.RunOutput{Target string; Findings []types.Finding; AgentsRan []string; Candidates int; Recon string; Workdir string; Artifacts []string}`, `pipeline.Run(ctx, cfg, lib, pool, progress) RunOutput`, `pipeline.RunWhitebox(...)`, `pipeline.RunGreybox(...)`, `pipeline.RunHost(...)`. Consumed by `cmd`, `repl`, `tui`.

- [ ] **Step 1: Write the failing test (offline integration test)** — In `pipeline_test.go`: build a `RunConfig{Target:"http://example.test", Offline:true, Workdir:<temp runs dir>}` and a STUBBED pool — define a `PoolCaller` interface (`CompleteRouted(ctx, task, system, user) (ModelRef, string, error)`, `Vote(...)`) and inject a fake that returns canned recon JSON `{}` for recon and a canned finding JSON array `[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200 OK Server: nginx","payload":"'","confidence":0.9}]` for exploitation; the stub vote returns confirmed. Run `Run(...)`; assert a `runs/ns-*` dir is created with `status.json` containing `"complete"`, `findings.json` non-empty and parseable into `[]types.Finding` with the SQLi title, `report.html` contains "SQLi", and the RL state file (`data/rl_state_go.json` under a temp base) was written.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/pipeline/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `pipeline.go` porting `neurosploit-rs/crates/harness/src/pipeline.rs`: port the prompt-doctrine constants VERBATIM from `pipeline.rs:25-80` (`RECON_SYS`, `REACT_DOCTRINE`, `DEPTH_DOCTRINE`, `VOTE_SYS`, `CODE_VOTE_SYS`, `CHAIN_SYS`, `SELECT_SYS`, `HOST_TOOLING`) plus `operatorDirectives(cfg)` and `toolDoctrine(mcpOn)`. `Run` (black-box): `pool.SetProgress(progress)`; recon (offline → `"{}"`); `selectAgents` (LLM select via `pool.CompleteRouted(TaskSelect,...)` + `parseStringArray`; fallback `heuristicSelect` with the `BASELINE` list + signals table copied from `pipeline.rs:519-560`); `exploitAgents` via `errgroup.WithContext`+`SetLimit(concurrency)`, each agent → `pool.CompleteRouted(TaskExploit,...)` → `extractFindings`; `dedupFindings`; `validate` (N-model vote, demote unconfirmed); `chainRound` (feed confirmed findings to chain agents) → validate again → dedup; `finish` (grounding.Gate, hygiene.Calibrate/DepthAudit/HygieneSummary, belief world model from findings, attackgraph.Enrich, rl.Update+Save, persist → `recon.json/.md`, `exploitation.md`, `findings.json/.md`, `report.html`, `status.json`). `extractFindings`: the lenient JSON coercion (`s()`, `conf()` accepting number/numeric-string/qualitative-word, `normSev()`, `dedupFindings()` by cwe|endpoint|title-prefix). `RunWhitebox`/`RunGreybox`/`RunHost`: same skeleton with their recon/source/host variants per `pipeline.rs`. Use a `PoolCaller` interface field so the test can stub model calls.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/pipeline/ && git commit -m "feat(go): add internal/pipeline orchestrator + offline integration test"`

## Task 15: `cmd/neurosploit` — cobra CLI

**Files:** Create `neurosploit-go/cmd/neurosploit/main.go`

**Interfaces:**
- Consumes: `pipeline`, `agents`, `models`, `pool`, `creds`, `integrations`, `repl`, `tui`, `types`.
- Produces: the `neurosploit` binary with subcommands `run,whitebox,greybox,host,pr,watch,tui,integrations,agents,models` (no args → `repl.Run`).

- [ ] **Step 1: Write the failing test** — This task's test is end-to-end via the binary: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go run ./cmd/neurosploit agents` prints JSON containing `"total":` with a number > 0. `go run ./cmd/neurosploit run http://example.test --offline` exits 0 and creates a `runs/ns-*` directory. `go run ./cmd/neurosploit models` prints provider lines including "anthropic" and "ollama". (Add `go get github.com/spf13/cobra` in this task.)
- [ ] **Step 2: Run test to verify it fails** — Run: `go run ./cmd/neurosploit agents`. Expected: FAIL — no main package / build error.
- [ ] **Step 3: Write minimal implementation** — Create `main.go` porting `neurosploit-rs/app/src/main.rs` (the clap CLI → cobra). `findBase()` (NEUROSPLOIT_BASE env else walk up ≤6 dirs to one containing `agents_md`). cobra root command `neurosploit` (no subcommand → `repl.Run(base)`). Subcommands with the exact flags from the spec: `run <url>` (`--model` repeated, `--max-agents` int default 0, `--vote-n` int default 3, `--offline`, `--subscription`, `--mcp`, `--creds`, `--focus`, `--jira`, `-v`); `whitebox <path>` (`--model`,`--max-agents`,`--vote-n` default 2,`--offline`,`--subscription`,`--jira`,`-v`); `greybox <path> --url <app>` (`--model`,`--creds`,`--focus`,`--max-agents`,`--vote-n`,`--offline`,`--subscription`,`--mcp`,`--jira`,`-v`); `host <target>` (`--model`,`--creds`,`--focus`,`--max-agents`,`--vote-n`,`--offline`,`--subscription`,`-v`); `pr <repo> <number>` (`--model`,`--vote-n` default 2,`--subscription`,`--comment`,`--jira`,`-v`); `watch <repo>` (`--branch` default main,`--interval` default 300,`--model`,`--subscription`,`--jira`,`-v`); `tui <url>` (`--model`,`--subscription`,`--mcp`,`-v`); `integrations [show|enable|disable] [github|gitlab|jira]`; `agents`; `models`. Helpers: `applyCreds(ctx, cfg, path)`, `runEngagement` (build pool via `pool.WithAuth`, set `workdir` to `runs/ns-<unix-ts>-<sanitized-target>`, set `rl_path` to `<base>/data/rl_state_go.json`, call the matching `pipeline.Run*`, `printFindings`, `postIntegrations`), `resolveSource` (local path or github clone via git), `sanitize`, `nowTs`, `writeStatus`.
- [ ] **Step 4: Run test to verify it passes** — Run: `go run ./cmd/neurosploit agents` and `go run ./cmd/neurosploit run http://example.test --offline`. Expected: both succeed; `agents` prints total>0; `run --offline` creates a runs/ dir.
- [ ] **Step 5: Commit** — `git add neurosploit-go/cmd/ neurosploit-go/go.mod neurosploit-go/go.sum && git commit -m "feat(go): add cmd/neurosploit cobra CLI"`

## Task 16: `internal/repl` — interactive REPL

**Files:** Create `neurosploit-go/internal/repl/repl.go`

**Interfaces:**
- Consumes: `pipeline`, `agents`, `models`, `pool`, `creds`, `integrations`, `types`, `github.com/peterh/liner`, `github.com/AlecAivazis/survey/v2`.
- Produces: `repl.Session{...}`, `repl.Run(base string) error`, `repl.ProjDir() string`. Consumed by `cmd`.

- [ ] **Step 1: Write the failing test** — In `repl_test.go`: `ProjDir()` returns `<cwd>/.neurosploit` and creates it. A `Session` save/load round-trips the persisted `session.json` (models, subscription, mcp, voteN, maxAgents, target, repo, auth, creds, instructions) — assert the JSON keys match the Rust `Snapshot` schema. (Add `go get github.com/peterh/liner github.com/AlecAivazis/survey/v2` in this task.)
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go test ./internal/repl/`. Expected: FAIL — undefined.
- [ ] **Step 3: Write minimal implementation** — Create `repl.go` porting `neurosploit-rs/app/src/repl.rs`: `Session` struct (models, subscription, mcp, voteN, maxAgents, target, repo, auth, creds, instructions). `Run(base)` uses `liner.NewLiner` for line editing + a history file at `.neurosploit/history`. Slash-commands: `/run`, `/status`, `/finding`, `/results`, `/expand`, `/pause`, `/continue`, `/integrations`, `/agents`, `/models`, `/report`, `/quit`. Background-run streaming via the progress channel into a `RunLive` (target, mode, phase, findings, agents/agents_done). `.neurosploit/` persistence: `session.json`, `runs.json`, `active_run.json` (JSON schemas matching the Rust `Snapshot`/`RunRecord`/`LiveCheckpoint`). `ProjDir()` = `<cwd>/.neurosploit`. `survey` multi-select for model choice.
- [ ] **Step 4: Run test to verify it passes** — Run: same. Expected: PASS.
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/repl/ neurosploit-go/go.mod neurosploit-go/go.sum && git commit -m "feat(go): add internal/repl interactive session"`

## Task 17: `internal/tui` — bubbletea "Mission Control"

**Files:** Create `neurosploit-go/internal/tui/tui.go`

**Interfaces:**
- Consumes: `pipeline`, `agents`, `models`, `pool`, `types`, `github.com/charmbracelet/bubbletea`+`bubbles`+`lipgloss`.
- Produces: `tui.Run(base string, cfg types.RunConfig) error`. Consumed by `cmd`.

- [ ] **Step 1: Write the failing test** — bubbletea programs are hard to unit-test, so this task's gate is compile + a build smoke test: `cd /home/tui/repos/NeuroSploit/neurosploit-go && go build ./internal/tui/` succeeds. (Add `go get github.com/charmbracelet/bubbletea github.com/charmbracelet/bubbles github.com/charmbracelet/lipgloss` in this task.)
- [ ] **Step 2: Run test to verify it fails** — Run: `go build ./internal/tui/`. Expected: FAIL — no Go files.
- [ ] **Step 3: Write minimal implementation** — Create `tui.go` porting `neurosploit-rs/app/src/tui.rs`: a bubbletea `Ui` model (target, models, mode, phase, started, feed deque, findings, targets, token totals, composer input, filterErrors, done, paused) implementing `Init/Update/View`. `ingest(raw string)` does phase tracking from progress lines (recon/planning/exploiting/validating/chaining/complete) and pulls live findings from `finding: [sev] title @ endpoint` lines. `feedSpan` colors lines (findings yellow, notify cyan, fail/error red, exec/curl orange, recon/vote/chain cyan, else gray). Layout via lipgloss: a status header (target·mode·phase·elapsed·findings·tokens), a body split 60/40 (activity feed | findings + targets), and a composer input that answers `summary`/`pause`/`errors`/`clear` locally without stopping the runner. `Run(base, cfg)` launches the engagement as a goroutine streaming to a channel and runs the bubbletea program.
- [ ] **Step 4: Run test to verify it passes** — Run: `go build ./internal/tui/`. Expected: PASS (builds clean).
- [ ] **Step 5: Commit** — `git add neurosploit-go/internal/tui/ neurosploit-go/go.mod neurosploit-go/go.sum && git commit -m "feat(go): add internal/tui bubbletea Mission Control"`

## Task 18: `AGENTS.md` — repo-root contributor guide for AI coding agents

**Files:** Create `/home/tui/repos/NeuroSploit/AGENTS.md`

**Interfaces:**
- Consumes: the decisions in the design spec (`docs/superpowers/specs/2026-06-30-neurosploit-go-port-design.md`).
- Produces: a CLAUDE.md-style instructions file at the repo root.

- [ ] **Step 1: Write the failing test** — There is no automated test for a doc; the gate is that the file exists and contains the required sections. Verify with: `test -f /home/tui/repos/NeuroSploit/AGENTS.md && grep -q 'Build & run' AGENTS.md && grep -q 'Forbidden' AGENTS.md && grep -q 'Dependency rules' AGENTS.md` — each must succeed.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit && test -f AGENTS.md && grep -q 'Build & run' AGENTS.md && grep -q 'Forbidden' AGENTS.md && grep -q 'Dependency rules' AGENTS.md`. Expected: FAIL (no such file).
- [ ] **Step 3: Write minimal implementation** — Create `AGENTS.md` at the repo root with these sections: **Project** (NeuroSploit is an autonomous multi-model pentest harness; two harnesses coexist — Rust `neurosploit-rs/` and Go `neurosploit-go/` — sharing repo-root `agents_md/` and `data/`); **Repo layout** (one line per Go package: `cmd/neurosploit` CLI; `internal/{types,agents,belief,pomdp,rl,grounding,hygiene,attackgraph,creds,models,pool,report,integrations,pipeline,repl,tui}`; plus `agents_md/`, `data/`, `templates/`); **Build & run (Go)** (`cd neurosploit-go && go build ./...`, `go run ./cmd/neurosploit run <url> --offline`, `go vet ./...`, `golangci-lint run`, `go test ./...`); **Go conventions** (standard `cmd/`+`internal/` layout; `context.Context` as first arg on blocking funcs; errors via `fmt.Errorf("...: %w", err)`; no panics on bad input — lenient coercion; rune-safe truncation; struct JSON tags must match the Rust serde schema exactly; one package = one concern); **Dependency rules** (stdlib first; only the 5 approved libs — cobra/bubbletea/liner/survey/x-sync; no YAML lib, creds parser is hand-rolled; new deps require a written note on why); **Concurrency** (goroutines + channels + `semaphore.Weighted` + `errgroup`; no external async runtime; `ctx.Done()` for cancel); **Forbidden actions** (no destructive/DoS logic in agents; authorized-testing-only; never store secrets in config files, only env-var names; never break the Rust↔Go JSON schema parity; do not edit `agents_md/` from the Go port; do not modify `neurosploit-rs/`); **Commit style** (conventional commits; one package per commit where practical; keep `docs/parity-rust-go.md` in sync); **Testing requirement** (every pure module lands with its `_test.go`; the offline pipeline integration test must stay green).
- [ ] **Step 4: Run test to verify it passes** — Run: the same `test -f ... && grep -q ...` chain. Expected: PASS.
- [ ] **Step 5: Commit** — `git add AGENTS.md && git commit -m "docs: add AGENTS.md contributor guide for AI coding agents"`

## Task 19: `docs/parity-rust-go.md` + final verification

**Files:** Create `/home/tui/repos/NeuroSploit/docs/parity-rust-go.md`

**Interfaces:**
- Consumes: the completed Go port + the Rust source.
- Produces: the Rust→Go parity checklist doc; a green full build/vet/test.

- [ ] **Step 1: Write the failing test** — Gate: `test -f /home/tui/repos/NeuroSploit/docs/parity-rust-go.md && grep -q 'internal/types' docs/parity-rust-go.md && grep -q 'internal/pipeline' docs/parity-rust-go.md`.
- [ ] **Step 2: Run test to verify it fails** — Run: `cd /home/tui/repos/NeuroSploit && test -f docs/parity-rust-go.md && grep -q 'internal/types' docs/parity-rust-go.md && grep -q 'internal/pipeline' docs/parity-rust-go.md`. Expected: FAIL (no such file).
- [ ] **Step 3: Write minimal implementation** — Create `docs/parity-rust-go.md` as a Markdown table mapping each Rust module → Go package with columns: **Rust source** (e.g. `harness/src/types.rs`), **Go package** (`internal/types`), **Public-API parity** (✅/⚠️/❌), **Test coverage** (`_test.go` name or "—"), **Verified behavior matches** (checkbox `[ ]`). One row per the 16 `internal/` packages + `cmd/neurosploit` (mapping `app/src/{main,repl,tui}.rs`). Fill the ✅/`_test.go` columns from the tasks just completed; leave the final "verified behavior matches" column as `[ ]` to be checked during execution. Also create `neurosploit-go/README.md` (short: one-paragraph what-it-is, build/run/test commands, note that it's a faithful Go port coexisting with `neurosploit-rs/` sharing `agents_md/`+`data/`). After writing the docs, run the final verification: `cd neurosploit-go && go vet ./... && go test ./... && go build ./...` — all three must succeed.
- [ ] **Step 4: Run test to verify it passes** — Run: `cd /home/tui/repos/NeuroSploit && test -f docs/parity-rust-go.md && grep -q 'internal/types' docs/parity-rust-go.md && grep -q 'internal/pipeline' docs/parity-rust-go.md` AND `cd neurosploit-go && go vet ./... && go test ./... && go build ./...`. Expected: PASS (doc exists; full Go build/vet/test green).
- [ ] **Step 5: Commit** — `git add docs/parity-rust-go.md neurosploit-go/README.md && git commit -m "docs: add Rust→Go parity checklist and README; verify full build"`
