# Greybox & Host Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire greybox and host modes end-to-end in `neurosploit-go` (CLI, REPL, TUI, creds, source resolve, tests).

**Architecture:** Shared helpers in `internal/engagement`, `internal/source`, and minimal `internal/integrations`. CLI/REPL/TUI call them; existing `pipeline.RunGreybox` / `RunHost` unchanged.

**Tech Stack:** Go 1.26, cobra, stdlib `os/exec` for git clone, existing `internal/creds` parser.

**Spec:** [`docs/superpowers/specs/2026-07-01-greybox-host-parity-design.md`](../specs/2026-07-01-greybox-host-parity-design.md)

---

## File map

| File | Responsibility |
|---|---|
| `internal/integrations/integrations.go` | Load JSON config; authed clone URLs |
| `internal/engagement/creds.go` | ApplyCreds, DetectMode, NormalizeURL |
| `internal/source/resolve.go` | Resolve local/GitHub repo paths |
| `cmd/neurosploit/main.go` | greybox/host/tui CLI wiring |
| `internal/repl/repl.go` | /creds, mode detection |
| `internal/pipeline/run.go` | finding_json progress lines |
| `docs/PARITY.md` | accurate status |

---

### Task 1: Minimal integrations package

**Files:**
- Create: `neurosploit-go/internal/integrations/integrations.go`
- Create: `neurosploit-go/internal/integrations/integrations_test.go`

- [ ] **Step 1: Write failing test**

```go
// integrations_test.go
func TestAuthedCloneURLGitHub(t *testing.T) {
	ig := Integrations{
		Github: GithubCfg{Enabled: true, TokenEnv: "TEST_GH_TOKEN"},
	}
	t.Setenv("TEST_GH_TOKEN", "secret")
	got := ig.AuthedCloneURL("https://github.com/acme/repo")
	want := "https://x-access-token:secret@github.com/acme/repo"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAuthedCloneURLDisabled(t *testing.T) {
	ig := Integrations{}
	url := "https://github.com/acme/repo"
	if ig.AuthedCloneURL(url) != url {
		t.Fatal("expected passthrough when disabled")
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd neurosploit-go && go test ./internal/integrations/... -run TestAuthedCloneURL -v`

- [ ] **Step 3: Implement**

```go
// integrations.go — structs match Rust serde JSON field names (lowercase keys)
type GithubCfg struct {
	Enabled  bool   `json:"enabled"`
	TokenEnv string `json:"token_env"`
	API      string `json:"api"`
}
type GitlabCfg struct {
	Enabled  bool   `json:"enabled"`
	TokenEnv string `json:"token_env"`
	Base     string `json:"base"`
}
type Integrations struct {
	Github GithubCfg `json:"github"`
	Gitlab GitlabCfg `json:"gitlab"`
}

func Load(dir string) Integrations { /* read dir/integrations.json or default */ }
func (ig Integrations) AuthedCloneURL(url string) string { /* port Rust logic */ }
```

- [ ] **Step 4: Run test — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/integrations/
git commit -m "feat(go): add minimal integrations for authed git clone"
```

---

### Task 2: engagement helpers — DetectMode + NormalizeURL

**Files:**
- Create: `neurosploit-go/internal/engagement/mode.go`
- Create: `neurosploit-go/internal/engagement/mode_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestDetectMode(t *testing.T) {
	cr := &creds.Creds{SSH: &creds.Ssh{Host: "10.0.0.1", User: "root", Password: "x"}}
	tests := []struct {
		repo, target string
		cr           *creds.Creds
		want         string
		wantErr      bool
	}{
		{"/repo", "http://app", nil, "greybox", false},
		{"/repo", "", nil, "whitebox", false},
		{"", "http://app", nil, "run", false},
		{"", "10.0.0.1", cr, "host", false},
		{"", "", nil, "", true},
	}
	for _, tc := range tests {
		got, err := DetectMode(tc.repo, tc.target, tc.cr)
		if tc.wantErr && err == nil {
			t.Fatalf("repo=%q target=%q expected error", tc.repo, tc.target)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("repo=%q target=%q got %q want %q", tc.repo, tc.target, got, tc.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	if NormalizeURL("example.com") != "https://example.com" {
		t.Fatal()
	}
	if NormalizeURL("http://x") != "http://x" {
		t.Fatal()
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cd neurosploit-go && go test ./internal/engagement/... -run 'TestDetectMode|TestNormalizeURL' -v`

- [ ] **Step 3: Implement mode.go**

```go
func DetectMode(repo, target string, cr *creds.Creds) (string, error) {
	switch {
	case repo != "" && target != "":
		return "greybox", nil
	case repo != "":
		return "whitebox", nil
	case target != "":
		if isHostTarget(target, cr) {
			return "host", nil
		}
		return "run", nil
	default:
		return "", fmt.Errorf("set /target and/or /repo first")
	}
}

func isHostTarget(target string, cr *creds.Creds) bool {
	if cr == nil || cr.HostInstruction() == nil {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(target))
	return !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://")
}

func NormalizeURL(url string) string {
	u := strings.TrimSpace(url)
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://" + u
}
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

---

### Task 3: engagement.ApplyCreds

**Files:**
- Create: `neurosploit-go/internal/engagement/apply_creds.go`
- Modify: `neurosploit-go/internal/engagement/engagement_test.go` (or new `apply_creds_test.go`)

- [ ] **Step 1: Write failing test for host instruction**

```go
func TestApplyCredsHostInstruction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte("ssh:\n  host: 10.0.0.1\n  user: root\n  password: x\n"), 0644)
	cfg := types.NewRunConfig("10.0.0.1")
	if err := ApplyCreds(context.Background(), &cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.Instructions == nil || !strings.Contains(*cfg.Instructions, "SSH ACCESS") {
		t.Fatalf("instructions = %v", cfg.Instructions)
	}
}
```

- [ ] **Step 2: Write failing test for auto-login (httptest)**

```go
func TestApplyCredsAutoLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	fmt.Fprintf(os.Create(path), "login:\n  url: %s\n  method: POST\n", srv.URL)
	cfg := types.NewRunConfig("http://app")
	if err := ApplyCreds(context.Background(), &cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth == nil {
		t.Fatal("expected auth from auto-login")
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement ApplyCreds** (port Rust `apply_creds`; stderr status lines via `fmt.Fprintf(os.Stderr, ...)`)

- [ ] **Step 5: Run — expect PASS**

- [ ] **Step 6: Commit**

---

### Task 4: source.Resolve

**Files:**
- Create: `neurosploit-go/internal/source/resolve.go`
- Create: `neurosploit-go/internal/source/resolve_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestResolveLocalPath(t *testing.T) {
	dir := t.TempDir()
	got, err := Resolve(dir, dir)
	if err != nil || got != dir {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestClassifyGitHubShorthand(t *testing.T) {
	if !isGitHubShorthand("acme/repo") {
		t.Fatal("expected shorthand")
	}
	if isGitHubShorthand("/absolute/path") {
		t.Fatal("absolute path is not shorthand")
	}
	if isGitHubShorthand("http://github.com/a/b") {
		t.Fatal("URL is not shorthand")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement Resolve** — classify, cache under `{base}/repos/{name}`, `git clone --depth 1`. Export `isGitHubShorthand` only if needed for tests (or test via Resolve with temp + skip clone test).

- [ ] **Step 4: Run — expect PASS** (clone test optional: tag `integration` or skip if git unavailable)

- [ ] **Step 5: Commit**

---

### Task 5: CLI greybox + host subcommands

**Files:**
- Modify: `neurosploit-go/cmd/neurosploit/main.go`

- [ ] **Step 1: Remove inline `applyCreds`; import engagement + source**

- [ ] **Step 2: Add greyboxCmd**

```go
func greyboxCmd() *cobra.Command {
	var url string
	// ... same flag pattern as runCmd ...
	cmd := &cobra.Command{
		Use:   "greybox <repo>",
		Short: "Review source and exploit the running app together",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base := findBase()
			repo, err := source.Resolve(base, args[0])
			if err != nil { return err }
			cfg := types.NewRunConfig(engagement.NormalizeURL(url))
			cfg.Repo = &repo
			// set flags...
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			return runEngagement(cmd.Context(), cfg, nil, mcp, "greybox", stubOrNil)
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "URL of the running application (required)")
	cmd.MarkFlagRequired("url")
	return cmd
}
```

- [ ] **Step 3: Add hostCmd** — target as arg, no URL normalize, `mcp` forced false in runEngagement call

- [ ] **Step 4: Register in rootCmd:** `root.AddCommand(..., greyboxCmd(), hostCmd())`

- [ ] **Step 5: Update runCmd/whiteboxCmd** to use `engagement.ApplyCreds`

- [ ] **Step 6: Smoke test**

```bash
cd neurosploit-go && go build ./cmd/neurosploit
./neurosploit greybox --help
./neurosploit host --help
./neurosploit greybox /tmp/foo --url localhost --offline 2>&1 | head -5
```

- [ ] **Step 7: Commit**

---

### Task 6: TUI --repo greybox

**Files:**
- Modify: `neurosploit-go/cmd/neurosploit/main.go` (`tuiCmd`)

- [ ] **Step 1: Add flags `--repo`, `--creds`, `--focus` to tuiCmd**

- [ ] **Step 2: Resolve repo, set mode, ApplyCreds, call tui.Run**

```go
mode := "run"
if repoFlag != "" {
	mode = "greybox"
	repoPath, err := source.Resolve(base, repoFlag)
	if err != nil { return err }
	cfg.Repo = &repoPath
}
cfg.Target = engagement.NormalizeURL(args[0])
engagement.ApplyCreds(cmd.Context(), &cfg, credsPath)
return tui.Run(base, cfg, mode, mcp)
```

- [ ] **Step 3: Build + manual smoke**

- [ ] **Step 4: Commit**

---

### Task 7: REPL /creds + mode detection

**Files:**
- Modify: `neurosploit-go/internal/repl/repl.go`
- Modify: `neurosploit-go/internal/repl/repl_test.go`

- [ ] **Step 1: Add `CredsPath string` to Session**

- [ ] **Step 2: Add `/creds` handler**

- [ ] **Step 3: Update backgroundRun**

```go
cr := (*creds.Creds)(nil)
if s.CredsPath != "" {
	cr = creds.Load(s.CredsPath)
}
mode, err := engagement.DetectMode(s.Repo, s.Target, cr)
if err != nil { fmt.Fprintln(out, err); return }
cfg := s.RunConfig()
if s.Repo != "" { cfg.Repo = &s.Repo }
_ = engagement.ApplyCreds(ctx, &cfg, s.CredsPath)
if s.live != nil { s.live.Mode = modeLabel(mode) }
outRun := engagement.Execute(ctx, s.Base, cfg, mode, s.MCP, stub, progress)
```

- [ ] **Step 4: Update `/show` and helpText**

- [ ] **Step 5: Add repl_test for /creds and DetectMode integration**

- [ ] **Step 6: Run `go test ./internal/repl/... -v`**

- [ ] **Step 7: Commit**

---

### Task 8: Progress line parity

**Files:**
- Modify: `neurosploit-go/internal/pipeline/run.go` (`parallelExploit`)

- [ ] **Step 1: After extractFindings loop, emit finding_json**

```go
for _, c := range f {
	sendProgress(progress, fmt.Sprintf("finding: [%s] %s @ %s", c.Severity, c.Title, c.Endpoint))
	if b, err := json.Marshal(c); err == nil {
		sendProgress(progress, "finding_json: "+string(b))
	}
}
```

- [ ] **Step 2: Host wording — use `test` prefix when `builder.host`**

Change fail/success lines from `exploit %s` to `test %s` when `builder.host == true`.

- [ ] **Step 3: Run pipeline tests**

Run: `cd neurosploit-go && go test ./internal/pipeline/... -v`

- [ ] **Step 4: Commit**

---

### Task 9: Offline integration tests

**Files:**
- Modify: `neurosploit-go/internal/pipeline/pipeline_test.go`

- [ ] **Step 1: Add TestRunGreyboxOffline**

```go
func TestRunGreyboxOffline(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-gb")
	wd := workdir
	repo := "/tmp/nonexistent-repo"
	cfg := types.NewRunConfig("http://example.test")
	cfg.Repo = &repo
	cfg.Offline = true
	cfg.Workdir = &wd
	cfg.MaxAgents = 1
	out := RunGreybox(context.Background(), cfg, lib, stubPool{reconJSON: `{}`, exploitJSON: `[]`}, progress)
	if out.Workdir != workdir {
		t.Fatalf("workdir = %q", out.Workdir)
	}
}
```

- [ ] **Step 2: Add TestRunHostOffline** — same pattern with `RunHost`, target `10.0.0.1`

- [ ] **Step 3: Run full suite**

Run: `cd neurosploit-go && go vet ./... && go test ./... -timeout 30s`

- [ ] **Step 4: Commit**

---

### Task 10: Update PARITY.md

**Files:**
- Modify: `docs/PARITY.md`

- [ ] **Step 1: Split pipeline row; add greybox/host wiring rows**

- [ ] **Step 2: Document Go extensions (host recon tool-loop, REPL host routing)**

- [ ] **Step 3: Commit**

```bash
git add docs/PARITY.md
git commit -m "docs: update PARITY.md for greybox/host wiring"
```

---

## Final verification

```bash
cd neurosploit-go
go vet ./...
go test ./... -timeout 30s
go build ./cmd/neurosploit
./neurosploit greybox /tmp --url http://example.com --offline -v
./neurosploit host 127.0.0.1 --offline -v
```

All tests green; CLI smoke runs complete.
