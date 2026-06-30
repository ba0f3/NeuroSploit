# NeuroSploit Go Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Rust parity gaps in `neurosploit-go/`: Rust-faithful pipeline orchestration (recon → TaskSelect → parallel exploit with agent prompts), embedded `agents_md/` for release builds, Cursor CLI provider, bash MCP allowlist with shell parsing, and Vietnamese hygiene terms.

**Architecture:** Replace the POMDP `Runner` with package-level `Run`/`RunWhitebox`/`RunGreybox`/`RunHost` ported from `neurosploit-rs/crates/harness/src/pipeline.rs`. Shared pure helpers live in focused files (`prompt.go`, `findings.go`, `select.go`, `persist.go`). Build-tag split for agent loading; new deps only `mvdan.cc/sh/v3`.

**Tech Stack:** Go 1.26, `golang.org/x/sync/errgroup`, `mvdan.cc/sh/v3/syntax`, existing cobra CLI.

**Spec:** `docs/superpowers/specs/2026-06-30-neurosploit-go-phase2-design.md`

**Port source of truth:** `neurosploit-rs/crates/harness/src/pipeline.rs` (read and port behavior verbatim for constants, heuristics, JSON coercion).

---

## File map

| File | Responsibility |
|---|---|
| `internal/agents/prompt.go` | `RenderPrompt(tmpl, vars)` |
| `internal/agents/agents.go` | Shared types + `parseMD` helper |
| `internal/agents/agents_load.go` | `//go:build !embed_agents` — disk `Load` |
| `internal/agents/agents_embed.go` | `//go:build embed_agents` — embedded `Load` |
| `internal/pool/pool.go` | Add `SetProgress`, `StopExploiting` |
| `internal/report/report.go` | Minimal `HTML()` for persist |
| `internal/pipeline/prompt.go` | Doctrine constants + `operatorDirectives`, `toolDoctrine` |
| `internal/pipeline/findings.go` | `extractFindings`, `dedupFindings`, `parseStringArray` |
| `internal/pipeline/select.go` | `selectAgents`, `heuristicSelect` |
| `internal/pipeline/persist.go` | `persist` artifact writer |
| `internal/pipeline/run.go` | `Run`, `RunOutput`, `finish`, `validate`, `chainRound` |
| `internal/pipeline/whitebox.go` | `RunWhitebox`, `RunGreybox`, `RunHost` |
| `internal/mcpbridge/allowlist.go` | Allowlist load/save/prompt |
| `internal/mcpbridge/parse.go` | `baseCommands(cmd string)` via sh syntax |

---

## Task 1: `agents.RenderPrompt` + build-tag split

**Files:**
- Create: `neurosploit-go/internal/agents/prompt.go`
- Create: `neurosploit-go/internal/agents/prompt_test.go`
- Create: `neurosploit-go/internal/agents/parse.go` (shared MD parsing)
- Modify: `neurosploit-go/internal/agents/agents.go` (types only)
- Create: `neurosploit-go/internal/agents/agents_load.go`
- Create: `neurosploit-go/internal/agents/agents_embed.go`
- Create: `neurosploit-go/internal/agents/agentsdata/.gitkeep`

- [ ] **Step 1: Write the failing test**

```go
// prompt_test.go
package agents

import "testing"

func TestRenderPrompt(t *testing.T) {
	got := RenderPrompt("Target {target}\nRecon: {recon_json}", map[string]string{
		"target":      "https://example.test",
		"recon_json":  `{"tech":"nginx"}`,
	})
	want := "Target https://example.test\nRecon: {\"tech\":\"nginx\"}"
	if got != want {
		t.Fatalf("RenderPrompt = %q, want %q", got, want)
	}
}

func TestRenderPromptUnknownKeyLeftAlone(t *testing.T) {
	got := RenderPrompt("{unknown}", map[string]string{})
	if got != "{unknown}" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/agents/ -run TestRenderPrompt -v`
Expected: FAIL — `RenderPrompt` undefined

- [ ] **Step 3: Write minimal implementation**

```go
// prompt.go
package agents

import "strings"

// RenderPrompt replaces {key} placeholders in agent prompt templates.
func RenderPrompt(tmpl string, vars map[string]string) string {
	out := tmpl
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}
```

Move `loadDir` + regex parsing from `agents.go` into `parse.go` as `parseAgentFile(name, kind, content string) Agent`. Keep `Agent`, `Library`, `Total()` in `agents.go`.

Split disk loader:

```go
// agents_load.go
//go:build !embed_agents

package agents

func Load(base string) Library { /* current Load body using filepath */ }
```

```go
// agents_embed.go
//go:build embed_agents

package agents

import "embed"

//go:embed agentsdata/**/*
var agentsFS embed.FS

func Load(_ string) Library { /* walk embed.FS, call parseAgentFile */ }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/agents/ -v`
Expected: PASS (existing disk-load test still passes without embed tag)

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/agents/
git commit -m "feat(go): add RenderPrompt and embed_agents build-tag split"
```

---

## Task 2: Pool `SetProgress` + `StopExploiting`

**Files:**
- Modify: `neurosploit-go/internal/pool/pool.go`
- Modify: `neurosploit-go/internal/pool/pool_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSetProgress(t *testing.T) {
	p := New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	ch := make(chan string, 1)
	p.SetProgress(ch)
	if p.Progress == nil {
		t.Fatal("Progress not set")
	}
}

func TestStopExploiting(t *testing.T) {
	p := New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	if p.StopExploiting() {
		t.Fatal("expected false before stop")
	}
	p.Stop()
	if !p.StopExploiting() {
		t.Fatal("expected true after Stop")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/pool/ -run 'TestSetProgress|TestStopExploiting' -v`
Expected: FAIL — methods undefined

- [ ] **Step 3: Write minimal implementation**

Add to `pool.go`:

```go
func (p *ModelPool) SetProgress(ch chan<- string) { p.Progress = ch }

func (p *ModelPool) StopExploiting() bool { return p.soft.Load() }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/pool/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/pool/
git commit -m "feat(go): add pool SetProgress and StopExploiting"
```

---

## Task 3: Minimal `internal/report` for persist

**Files:**
- Create: `neurosploit-go/internal/report/report.go`
- Create: `neurosploit-go/internal/report/report_test.go`

Port `HTML()` from `neurosploit-rs/crates/harness/src/report.rs` (sort by severity, dark CSS, attackgraph Mermaid block). Typst/PDF is out of scope for this task.

- [ ] **Step 1: Write the failing test**

```go
func TestHTMLContainsFinding(t *testing.T) {
	html := HTML("http://example.test", []types.Finding{{
		Title: "SQLi", Severity: "Critical", Agent: "sqli", Endpoint: "/x",
	}})
	if !strings.Contains(html, "SQLi") || !strings.Contains(html, "NeuroSploit") {
		t.Fatalf("HTML missing expected content: %s", html[:min(200, len(html))])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/report/ -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Write minimal implementation**

Port `HTML`, `sevRank`, `sevColor`, `esc` from Rust `report.rs:33-104`. Import `internal/attackgraph` for `Mermaid()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/report/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/report/
git commit -m "feat(go): add minimal report.HTML for pipeline persist"
```

---

## Task 4: Pipeline finding extraction helpers

**Files:**
- Create: `neurosploit-go/internal/pipeline/findings.go`
- Create: `neurosploit-go/internal/pipeline/findings_test.go`

Port `extract_findings`, `s`, `conf`, `norm_sev`, `dedup_findings` from Rust `pipeline.rs:753-870`.

- [ ] **Step 1: Write the failing test**

```go
func TestExtractFindingsJSONArray(t *testing.T) {
	text := `Here are findings:
[{"title":"SQLi","severity":"High","cwe":"CWE-89","endpoint":"/id","payload":"'","evidence":"HTTP/1.1 200 OK Server: nginx","confidence":0.9}]`
	fs := extractFindings(text, "sqli_error")
	if len(fs) != 1 {
		t.Fatalf("len = %d", len(fs))
	}
	if fs[0].Title != "SQLi" || fs[0].Agent != "sqli_error" {
		t.Fatalf("got %+v", fs[0])
	}
}

func TestParseStringArray(t *testing.T) {
	got := parseStringArray(`choose: ["sqli_error","xss_reflected"]`)
	if len(got) != 2 || got[0] != "sqli_error" {
		t.Fatalf("got %v", got)
	}
}

func TestDedupFindings(t *testing.T) {
	a := types.Finding{CWE: "CWE-89", Endpoint: "/x", Title: "SQL injection"}
	b := types.Finding{CWE: "CWE-89", Endpoint: "/x", Title: "SQL injection variant"}
	out := dedupFindings([]types.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("dedup len = %d", len(out))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run 'TestExtract|TestParse|TestDedup' -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

Port logic from Rust. Use `encoding/json` with `map[string]interface{}` for lenient coercion. `dedupFindings` keys on `cwe|endpoint|title-prefix(12 runes)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run 'TestExtract|TestParse|TestDedup' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/pipeline/findings.go neurosploit-go/internal/pipeline/findings_test.go
git commit -m "feat(go): add pipeline finding extraction and dedup helpers"
```

---

## Task 5: Pipeline agent selection

**Files:**
- Create: `neurosploit-go/internal/pipeline/prompt.go` (doctrine constants)
- Create: `neurosploit-go/internal/pipeline/select.go`
- Create: `neurosploit-go/internal/pipeline/select_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestHeuristicSelectBaseline(t *testing.T) {
	ranked := []agents.Agent{{Name: "sqli_error", Title: "SQLi", CWE: "CWE-89"}}
	got := heuristicSelect(ranked, `{}`, "", 5)
	if len(got) == 0 || got[0].Name != "sqli_error" {
		t.Fatalf("got %v", got)
	}
}

func TestHeuristicSelectGraphQLSignal(t *testing.T) {
	ranked := []agents.Agent{
		{Name: "graphql_introspection", Title: "GraphQL", CWE: "CWE-200"},
		{Name: "sqli_error", Title: "SQLi", CWE: "CWE-89"},
	}
	got := heuristicSelect(ranked, `{"apis":["graphql"]}`, "", 5)
	if len(got) == 0 || got[0].Name != "graphql_introspection" {
		t.Fatalf("expected graphql first, got %v", namesOf(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run TestHeuristic -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `prompt.go`, copy constants verbatim from Rust `pipeline.rs:25-80, 472, 902`:
- `reconSys`, `selectSys`, `voteSys`, `codeVoteSys`, `chainSys`, `reactDoctrine`, `depthDoctrine`, `hostTooling`, `hostReconSys`
- `operatorDirectives(cfg types.RunConfig) string`
- `toolDoctrine(mcpOn bool) string`

In `select.go`, port `heuristic_select` with `BASELINE` list and `signals` table from Rust `pipeline.rs:518-595`. Port `selectAgents` calling `pool.Complete("select", pool.TaskSelect, selectSys, user)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run TestHeuristic -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/pipeline/prompt.go neurosploit-go/internal/pipeline/select.go neurosploit-go/internal/pipeline/select_test.go
git commit -m "feat(go): add pipeline doctrine constants and agent selection heuristics"
```

---

## Task 6: Pipeline `Run` (black-box) + offline integration test

**Files:**
- Create: `neurosploit-go/internal/pipeline/run.go`
- Create: `neurosploit-go/internal/pipeline/persist.go`
- Modify: `neurosploit-go/internal/pipeline/pipeline.go` (remove old Runner OR move to `runner_legacy.go` deleted)
- Rewrite: `neurosploit-go/internal/pipeline/pipeline_test.go`

- [ ] **Step 1: Write the failing integration test**

```go
type stubPool struct {
	reconJSON string
	exploitJSON string
}

func (s stubPool) SetProgress(chan<- string) {}
func (s stubPool) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	ref := models.ModelRef{Provider: "offline", Model: "stub"}
	switch task {
	case pool.TaskRecon:
		return ref, s.reconJSON, nil
	case pool.TaskSelect:
		return ref, `["sqli_error"]`, nil
	case pool.TaskExploit:
		return ref, s.exploitJSON, nil
	default:
		return ref, "{}", nil
	}
}
func (s stubPool) Vote(system, user string, n int, skip string) (int, int) { return n, n }
func (s stubPool) StopExploiting() bool { return false }

func TestRunOfflineIntegration(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-test")
	wd := workdir
	rlPath := filepath.Join(t.TempDir(), "rl_state_go.json")
	cfg := types.NewRunConfig("http://example.test")
	cfg.Offline = false // stub pool simulates live
	cfg.Workdir = &wd
	cfg.RLPath = &rlPath
	cfg.MaxAgents = 1
	cfg.VoteN = 1

	stub := stubPool{
		reconJSON: `{}`,
		exploitJSON: `[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200 OK Server: nginx","payload":"'","confidence":0.9}]`,
	}
	progress := make(chan string, 64)
	go func() { for range progress {} }()

	out := Run(context.Background(), cfg, lib, stub, progress)
	if len(out.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if out.Findings[0].Title != "SQLi" {
		t.Fatalf("got %+v", out.Findings[0])
	}
	data, err := os.ReadFile(filepath.Join(workdir, "findings.json"))
	if err != nil {
		t.Fatalf("findings.json: %v", err)
	}
	if !strings.Contains(string(data), "SQLi") {
		t.Fatalf("findings.json content: %s", data)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run TestRunOfflineIntegration -v`
Expected: FAIL — `Run` undefined

- [ ] **Step 3: Write minimal implementation**

Define in `run.go`:

```go
type RunOutput struct {
	Target     string            `json:"target"`
	Findings   []types.Finding   `json:"findings"`
	AgentsRan  []string          `json:"agents_ran"`
	Candidates int               `json:"candidates"`
	Recon      string            `json:"recon"`
	Workdir    string            `json:"workdir"`
	Artifacts  []string          `json:"artifacts"`
}

type PoolCaller interface {
	SetProgress(chan<- string)
	Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error)
	Vote(system, user string, n int, skip string) (confirmed, total int)
	StopExploiting() bool
}
```

Implement `Run` following Rust `run()` at `pipeline.rs:83-228`:
1. Progress: loaded agents line
2. Recon (offline → `"{}"`)
3. RL-ranked vulns, cap by `MaxAgents`
4. `selectAgents` → filter ranked by chosen names → dedup
5. Parallel exploit via `errgroup.SetLimit(cfg.Concurrency)` — each agent uses `ag.System` and user prompt with `agents.RenderPrompt(ag.User, vars)` wrapped in authorized-engagement template from Rust lines 178-190
6. `dedupFindings` → `validate` → `chainRound` → `finish`
7. Return `RunOutput`

Implement `validate`, `chainRound`, `finish` in `run.go` (port Rust lines 439-707). `finish` calls `grounding.Gate`, `hygiene.Calibrate/DepthAudit/HygieneSummary`, `attackgraph.Enrich`, `rl.Update+Save`, `persist`.

Implement `persist` in `persist.go` (port Rust `pipeline.rs:708-751`): write `recon.json`, `recon.md`, `exploitation.md`, `findings.json`, `findings.md`, `report.html`, `status.json`.

Delete or replace old `Runner` in `pipeline.go` — remove POMDP loop from exported API.

Add dependency: `go get golang.org/x/sync`

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run TestRunOfflineIntegration -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/pipeline/ neurosploit-go/go.mod neurosploit-go/go.sum
git commit -m "feat(go): replace Runner with Rust-faithful Run orchestrator"
```

---

## Task 7: Pipeline `RunWhitebox`, `RunGreybox`, `RunHost`

**Files:**
- Create: `neurosploit-go/internal/pipeline/whitebox.go`
- Create: `neurosploit-go/internal/pipeline/whitebox_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRunWhiteboxOffline(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-wb")
	wd := workdir
	cfg := types.NewRunConfig("/tmp/nonexistent-repo")
	cfg.Offline = true
	cfg.Workdir = &wd
	cfg.MaxAgents = 1
	progress := make(chan string, 8)
	go func() { for range progress {} }()
	out := RunWhitebox(context.Background(), cfg, lib, stubPool{reconJSON: `{}`, exploitJSON: `[]`}, progress)
	if out.Workdir != workdir {
		t.Fatalf("workdir = %q", out.Workdir)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -run TestRunWhiteboxOffline -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

Port `run_whitebox`, `run_greybox`, `run_host` from Rust `pipeline.rs:232-468, 908-999`. Each reuses `selectAgents`, parallel exploit with agent prompts, `validate`, `finish`. Whitebox uses `collectRepoContext` (port helper reading up to 120k bytes from path). Greybox adds code-leads recon pass. Host uses `lib.Infra` catalog and `hostReconSys`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/pipeline/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/pipeline/whitebox.go neurosploit-go/internal/pipeline/whitebox_test.go
git commit -m "feat(go): add RunWhitebox, RunGreybox, RunHost pipeline entrypoints"
```

---

## Task 8: CLI wiring

**Files:**
- Modify: `neurosploit-go/cmd/neurosploit/main.go`

- [ ] **Step 1: Manual verification checklist (no automated test for main)**

After changes, these must succeed:
- `go run ./cmd/neurosploit agents --list` prints agents
- `go run ./cmd/neurosploit run http://example.test --offline` exits 0

- [ ] **Step 2: Implement changes**

Replace `realRun` / `offlineRun`:

```go
func runEngagement(ctx context.Context, cfg types.RunConfig, cr *creds.Creds, mcp, verbose bool, mode string) error {
	base := findBase()
	lib := agents.Load(base)
	// build pool, mcp config (existing)
	workdir := filepath.Join("runs", fmt.Sprintf("ns-%d-%s", time.Now().Unix(), sanitize(cfg.Target)))
	cfg.Workdir = &workdir
	rl := filepath.Join(base, "data", "rl_state_go.json")
	cfg.RLPath = &rl
	cfg.Verbose = verbose
	_ = os.MkdirAll(workdir, 0755)

	progress := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range progress {
			fmt.Println(line)
		}
	}()

	var out pipeline.RunOutput
	switch mode {
	case "run":
		out = pipeline.Run(ctx, cfg, lib, p, progress)
	case "whitebox":
		out = pipeline.RunWhitebox(ctx, cfg, lib, p, progress)
	// greybox, host as subcommands added
	}
	close(progress)
	<-done
	printFindings(out.Findings)
	fmt.Printf("artifacts: %s\n", strings.Join(out.Artifacts, ", "))
	return nil
}
```

Remove `pipeline.New(stub, reg, wm, cr)` and `registry` usage from run path. Keep `offlineRun` using stub `PoolCaller` that returns canned JSON.

Wire `cfg.Verbose` from `-v` flag.

- [ ] **Step 3: Verify**

Run:
```bash
cd neurosploit-go && go run ./cmd/neurosploit run http://example.test --offline
cd neurosploit-go && go vet ./... && go test ./...
```
Expected: offline run creates `runs/ns-*` with `status.json`; all tests pass

- [ ] **Step 4: Commit**

```bash
git add neurosploit-go/cmd/neurosploit/main.go
git commit -m "feat(go): wire CLI to pipeline.Run with progress and artifacts"
```

---

## Task 9: Cursor provider

**Files:**
- Modify: `neurosploit-go/internal/models/models.go`
- Modify: `neurosploit-go/internal/models/models_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestProviderCursor(t *testing.T) {
	var found bool
	for _, p := range Providers() {
		if p.Key == "cursor" {
			found = true
			if p.Kind != "cli" {
				t.Fatalf("kind = %s", p.Kind)
			}
		}
	}
	if !found {
		t.Fatal("cursor provider missing")
	}
	if !MCPSupported("cursor") {
		t.Fatal("cursor should support MCP")
	}
	if CLIBinaryFor("cursor") == "" {
		t.Fatal("CLIBinaryFor cursor empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/models/ -run TestProviderCursor -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

Add provider entry. Update `CLIBinaryFor`:

```go
case "cursor":
	if BinaryInPath("agent") {
		return "agent"
	}
	return "cursor-agent"
```

Add `chatCursorCLI` branch in `ChatCLI`:

```go
case "agent", "cursor-agent":
	args := []string{bin, "-p", "--model", model, "--output-format", "text", "--trust"}
	if mcpConfig != "" {
		args = append(args, "--mcp-config", mcpConfig) // if CLI supports; else skip
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(prompt)
	// 600s timeout, capture stdout
```

Route cursor provider to this branch via `CLIBinaryFor` returning `agent` or `cursor-agent`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/models/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/models/
git commit -m "feat(go): add Cursor CLI subscription provider"
```

---

## Task 10: Bash MCP allowlist + shell parsing

**Files:**
- Create: `neurosploit-go/internal/mcpbridge/parse.go`
- Create: `neurosploit-go/internal/mcpbridge/allowlist.go`
- Modify: `neurosploit-go/internal/mcpbridge/mcpbridge.go`
- Modify: `neurosploit-go/internal/mcpbridge/mcpbridge_test.go`

- [ ] **Step 1: Add dependency**

Run: `cd neurosploit-go && go get mvdan.cc/sh/v3`

- [ ] **Step 2: Write the failing tests**

```go
func TestBaseCommandsPipeline(t *testing.T) {
	cmds, err := baseCommands("curl -s https://x | jq .")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 2 || cmds[0] != "curl" {
		t.Fatalf("got %v", cmds)
	}
}

func TestAllowlistDenyNonTTY(t *testing.T) {
	al := Allowlist{Commands: []string{"echo"}}
	if al.Permits([]string{"curl"}, false, nil) {
		t.Fatal("curl should be denied without TTY prompt")
	}
}

func TestAllowlistPermitsListed(t *testing.T) {
	al := Allowlist{Commands: []string{"echo"}}
	if !al.Permits([]string{"echo"}, false, nil) {
		t.Fatal("echo should be permitted")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd neurosploit-go && go test ./internal/mcpbridge/ -run 'TestBaseCommands|TestAllowlist' -v`
Expected: FAIL

- [ ] **Step 4: Write minimal implementation**

`parse.go`: walk `syntax.Parser` AST, collect first word of each `CallExpr` in pipelines.

`allowlist.go`:
```go
type Allowlist struct {
	Commands  []string `json:"commands"`
	TrustAll  bool     `json:"trust_all"`
}
func LoadAllowlist(dir string) (*Allowlist, error)
func (a *Allowlist) Save(dir string) error
func (a *Allowlist) Permits(bases []string, tty bool, prompter func(cmd string) AllowDecision) bool
```

Update `handleBash`: parse → dangerous check → allowlist check → `exec.Command("sh", "-c", cmd)`.

Session `trust_all` is in-memory on `Registry` struct field.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd neurosploit-go && go test ./internal/mcpbridge/ -v`
Expected: PASS (existing echo test still passes)

- [ ] **Step 6: Commit**

```bash
git add neurosploit-go/internal/mcpbridge/ neurosploit-go/go.mod neurosploit-go/go.sum
git commit -m "feat(go): bash MCP allowlist with mvdan/sh command parsing"
```

---

## Task 11: Vietnamese hygiene

**Files:**
- Modify: `neurosploit-go/internal/hygiene/hygiene.go`
- Modify: `neurosploit-go/internal/hygiene/hygiene_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestCalibrateVietnameseWeasel(t *testing.T) {
	fs := []types.Finding{{
		Title: "DoS", Severity: "High", CWE: "CWE-770",
		Endpoint: "https://a/x", Evidence: "có thể gây quá tải", Payload: "",
	}}
	notes := Calibrate(&fs)
	if fs[0].Severity != "Medium" {
		t.Fatalf("severity = %s", fs[0].Severity)
	}
	if len(notes) == 0 {
		t.Fatal("expected calibration note")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd neurosploit-go && go test ./internal/hygiene/ -run TestCalibrateVietnamese -v`
Expected: FAIL (severity stays High)

- [ ] **Step 3: Write minimal implementation**

Append to `WEASEL`:
`"có thể "`, `"có lẽ"`, `"tiềm năng"`, `"khả năng"`, `"có khả năng"`, `"nếu như"`, `"trong trường hợp"`, `"dường như"`, `"có thể sẽ"`

Append to `ExposureKeywords`:
`"tiết lộ"`, `"lộ thông tin"`, `"phiên bản"`, `"cấu hình"`, `"thiếu bảo mật"`, `"rò rỉ"`, `"phơi bày"`

(`"banner"` already present.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd neurosploit-go && go test ./internal/hygiene/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/hygiene/
git commit -m "feat(go): add Vietnamese hygiene weasel words and exposure keywords"
```

---

## Task 12: Docs + final verification

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/parity-rust-go.md` (create if missing)
- Modify: `neurosploit-go/README.md`

- [ ] **Step 1: Update AGENTS.md**

Add notes:
- New dep `mvdan.cc/sh/v3` for mcpbridge bash parsing (requires written justification — authorized pentest tool gate)
- Release build: `rsync -a agents_md/ internal/agents/agentsdata/ && go build -tags embed_agents ./cmd/neurosploit`

- [ ] **Step 2: Update parity doc**

Set `internal/pipeline` row to ✅ with `_test.go` and note phase-2 Run parity.

- [ ] **Step 3: Final gate**

Run:
```bash
cd neurosploit-go && go vet ./... && go test ./... && go build ./...
go run ./cmd/neurosploit run http://example.test --offline
```
Expected: all green; offline run produces `runs/ns-*` artifacts.

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md docs/parity-rust-go.md neurosploit-go/README.md
git commit -m "docs: update parity checklist and AGENTS.md for phase 2"
```

---

## Self-review (plan vs spec)

| Spec requirement | Task |
|---|---|
| Pipeline Run + 4 modes | Tasks 6–7 |
| agents.Load + TaskSelect + agent prompts | Tasks 1, 5, 6 |
| `{target}` / `{recon_json}` substitution | Task 1 + 6 |
| Embed agents_md build-tag | Task 1 |
| Cursor provider | Task 9 |
| Bash MCP allowlist + sh parse | Task 10 |
| Vietnamese hygiene | Task 11 |
| Progress logging + `-v` | Tasks 6, 8 |
| REPL/TUI out of scope | Not in plan ✓ |
| report.html persist | Task 3 + 6 |
| `mvdan.cc/sh/v3` dep documented | Tasks 10, 12 |

No TBD placeholders. `PoolCaller.StopExploiting` maps to `pool.Stop()` / `IsStopped()`.
