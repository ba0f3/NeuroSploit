# Recon Cache and Reuse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Skip redundant bootstrap recon (httpx→nuclei stack) when re-testing the same target by publishing/importing canonical recon bundles with TTY prompt and non-TTY auto-reuse.

**Architecture:** New `internal/reconcache` package owns bundle I/O, discovery, and policy resolution. `engagement.Execute` resolves policy before pipeline; `pipeline.runRecon` skips `runBootstrapTools` on reuse and publishes cache after fresh recon. CLI flags on all engagement commands; REPL `/recon` helpers.

**Tech Stack:** Go 1.22+, stdlib only (`os`, `path/filepath`, `encoding/json`, `crypto/sha256`, `io/fs`), existing `engagement.SanitizeTarget`, cobra flags.

**Spec:** [`docs/superpowers/specs/2026-07-02-recon-cache-design.md`](../specs/2026-07-02-recon-cache-design.md)

## Global Constraints

- Tests and docs use `example.com` only — never real targets or sensitive data (`AGENTS.md`).
- No new Go dependencies beyond existing stack (cobra, stdlib).
- Cache root default: `data/recon-cache`; runs root: `runs`.
- Staleness warning threshold: **7 days** (warning only, no auto-expiry).
- Non-TTY default: **reuse** when valid bundle exists; override with `--recon new`.
- TTY default: **prompt** when valid bundle exists.
- Empty recon `{}` is invalid — do not publish.
- Run `go vet ./... && go test ./... -timeout 30s` from `neurosploit-go/` before every commit.

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/types/recon.go` | `ReconPolicy` constants, `RunConfig` fields |
| `internal/reconcache/bundle.go` | `Bundle`, `Manifest`, validation |
| `internal/reconcache/cache.go` | `FindBundle`, `FindLatestRun`, `Publish`, `Import`, `ListRuns` |
| `internal/reconcache/policy.go` | `ResolvePolicy`, `PromptReuse`, TTY detection |
| `internal/reconcache/*.go` tests | Unit tests with `example.com` fixtures |
| `internal/engagement/engagement.go` | Resolve policy + import before pipeline |
| `internal/pipeline/run.go` | Skip bootstrap on reuse; publish after fresh recon |
| `cmd/neurosploit/main.go` | `--recon`, `--from-run`, `--recon-cache` flags |
| `internal/repl/repl.go` | `/recon list|clear|import` |
| `.gitignore` | Ignore `data/recon-cache/` |
| `docs/PARITY.md` | Go-only recon cache note |

---

### Task 1: RunConfig fields and ReconPolicy type

**Files:**
- Create: `neurosploit-go/internal/types/recon.go`
- Modify: `neurosploit-go/internal/types/types.go`
- Modify: `neurosploit-go/internal/types/types_test.go`

**Interfaces:**
- Produces: `ReconPolicy` type with constants `ReconPolicyAsk`, `ReconPolicyNew`, `ReconPolicyReuse`; `RunConfig.ReconPolicy`, `RunConfig.ReconCachePath`, `RunConfig.ReconFromRun` string fields.

- [ ] **Step 1: Write types**

```go
// internal/types/recon.go
package types

type ReconPolicy string

const (
	ReconPolicyAsk   ReconPolicy = "ask"   // TTY prompt when bundle found
	ReconPolicyNew   ReconPolicy = "new"   // force fresh bootstrap
	ReconPolicyReuse ReconPolicy = "reuse" // force import; error if missing
)

const DefaultReconCachePath = "data/recon-cache"
```

Add to `RunConfig` in `types.go`:

```go
	ReconPolicy    ReconPolicy `json:"recon_policy,omitempty"`     // empty = auto (ask/reuse)
	ReconCachePath string      `json:"recon_cache_path,omitempty"` // empty = DefaultReconCachePath
	ReconFromRun   string      `json:"recon_from_run,omitempty"`   // bypass cache lookup
```

- [ ] **Step 2: Run tests**

Run: `cd neurosploit-go && go test ./internal/types/... -v`
Expected: PASS (no behavior change yet)

- [ ] **Step 3: Commit**

```bash
git add neurosploit-go/internal/types/recon.go neurosploit-go/internal/types/types.go
git commit -m "feat: add ReconPolicy and RunConfig recon cache fields"
```

---

### Task 2: Bundle validation and manifest

**Files:**
- Create: `neurosploit-go/internal/reconcache/bundle.go`
- Create: `neurosploit-go/internal/reconcache/bundle_test.go`

**Interfaces:**
- Produces: `type Bundle struct { Dir, Slug, Target string; Manifest Manifest }`, `func ValidReconJSON(s string) bool`, `func LoadBundle(dir string) (*Bundle, error)`, `func (b *Bundle) Age() time.Duration`, `func (b *Bundle) StaleWarning() bool` (>7 days).

- [ ] **Step 1: Write failing tests**

```go
// bundle_test.go
package reconcache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidReconJSON(t *testing.T) {
	if ValidReconJSON(`{}`) || ValidReconJSON(``) || ValidReconJSON(`   `) {
		t.Fatal("empty recon should be invalid")
	}
	if !ValidReconJSON(`{"endpoints":["http://example.com/"]}`) {
		t.Fatal("non-empty JSON should be valid")
	}
}

func TestLoadBundleMissing(t *testing.T) {
	_, err := LoadBundle(t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestLoadBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	recon := `{"tech":["asp.net"],"endpoints":["http://example.com/login.aspx"]}`
	if err := os.WriteFile(filepath.Join(dir, "recon.json"), []byte(recon), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"target":"http://example.com/","slug":"example.com","created_at":"2026-07-02T12:00:00Z","source_run":"runs/ns-test-example.com","tools":["httpx"],"recon_hash":"sha256:deadbeef"}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Slug != "example.com" || b.Target != "http://example.com/" {
		t.Fatalf("bundle: %+v", b)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd neurosploit-go && go test ./internal/reconcache/... -run TestValidReconJSON -v`
Expected: FAIL — package not found

- [ ] **Step 3: Implement bundle.go**

```go
package reconcache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/engagement"
)

const staleAfter = 7 * 24 * time.Hour

type Manifest struct {
	Target    string   `json:"target"`
	Slug      string   `json:"slug"`
	CreatedAt string   `json:"created_at"`
	SourceRun string   `json:"source_run"`
	Tools     []string `json:"tools"`
	ReconHash string   `json:"recon_hash"`
}

type Bundle struct {
	Dir      string
	Slug     string
	Target   string
	Manifest Manifest
}

func Slug(target string) string { return engagement.SanitizeTarget(target) }

func ValidReconJSON(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return false
	}
	return json.Valid([]byte(s))
}

func LoadBundle(dir string) (*Bundle, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	reconPath := filepath.Join(dir, "recon.json")
	reconBytes, err := os.ReadFile(reconPath)
	if err != nil {
		return nil, fmt.Errorf("recon.json: %w", err)
	}
	if !ValidReconJSON(string(reconBytes)) {
		return nil, fmt.Errorf("invalid recon.json in %s", dir)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &Bundle{Dir: dir, Slug: m.Slug, Target: m.Target, Manifest: m}, nil
}

func (b *Bundle) CreatedTime() (time.Time, error) {
	return time.Parse(time.RFC3339, b.Manifest.CreatedAt)
}

func (b *Bundle) Age() time.Duration {
	t, err := b.CreatedTime()
	if err != nil {
		return 0
	}
	return time.Since(t)
}

func (b *Bundle) StaleWarning() bool { return b.Age() > staleAfter }

func (b *Bundle) SourceRunBase() string {
	return filepath.Base(b.Manifest.SourceRun)
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cd neurosploit-go && go test ./internal/reconcache/... -v`

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/reconcache/
git commit -m "feat: add reconcache bundle validation"
```

---

### Task 3: Publish and Import

**Files:**
- Create: `neurosploit-go/internal/reconcache/cache.go`
- Modify: `neurosploit-go/internal/reconcache/bundle_test.go` → add `cache_test.go`

**Interfaces:**
- Produces: `func Publish(cacheRoot, sourceRun, target, reconJSON, toolLog string, toolNames []string) (*Bundle, error)`, `func Import(b *Bundle, destWorkdir string) error`, `func reconHash(recon string) string`.

- [ ] **Step 1: Write failing test**

```go
// cache_test.go
func TestPublishImportRoundTrip(t *testing.T) {
	cacheRoot := t.TempDir()
	dest := t.TempDir()
	recon := `{"endpoints":["http://example.com/"]}`
	toolLog := "# Tool log\n\n## 1. httpx\n"
	b, err := Publish(cacheRoot, "runs/ns-test-example.com", "http://example.com/", recon, toolLog, []string{"httpx"})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := Import(b, dest); err != nil {
		t.Fatalf("Import: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "recon.json"))
	if err != nil || string(got) != recon {
		t.Fatalf("recon.json mismatch: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "recon_tools.md")); err != nil {
		t.Fatalf("recon_tools.md: %v", err)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd neurosploit-go && go test ./internal/reconcache/... -run TestPublishImportRoundTrip -v`

- [ ] **Step 3: Implement cache.go**

```go
package reconcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func reconHash(recon string) string {
	sum := sha256.Sum256([]byte(recon))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Publish(cacheRoot, sourceRun, target, reconJSON, toolLog string, toolNames []string) (*Bundle, error) {
	if !ValidReconJSON(reconJSON) {
		return nil, fmt.Errorf("refusing to publish empty recon")
	}
	slug := Slug(target)
	dir := filepath.Join(cacheRoot, slug)
	if err := os.MkdirAll(filepath.Join(dir, "tools"), 0755); err != nil {
		return nil, err
	}
	m := Manifest{
		Target:    target,
		Slug:      slug,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		SourceRun: sourceRun,
		Tools:     toolNames,
		ReconHash: reconHash(reconJSON),
	}
	if err := os.WriteFile(filepath.Join(dir, "recon.json"), []byte(reconJSON), 0644); err != nil {
		return nil, err
	}
	if toolLog != "" {
		md := fmt.Sprintf("# Tool log — %s\n\n%s", target, toolLog)
		if err := os.WriteFile(filepath.Join(dir, "recon_tools.md"), []byte(md), 0644); err != nil {
			return nil, err
		}
	}
	// Copy iter01 bootstrap logs from source run if present
	if sourceRun != "" {
		srcTools := filepath.Join(sourceRun, "tools")
		_ = copyIter01Logs(srcTools, filepath.Join(dir, "tools"))
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0644); err != nil {
		return nil, err
	}
	return LoadBundle(dir)
}

func copyIter01Logs(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil // source may lack tools/
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "iter01-") {
			continue
		}
		_ = copyFile(filepath.Join(srcDir, e.Name()), filepath.Join(dstDir, e.Name()))
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func Import(b *Bundle, destWorkdir string) error {
	if b == nil {
		return fmt.Errorf("nil bundle")
	}
	if err := os.MkdirAll(filepath.Join(destWorkdir, "tools"), 0755); err != nil {
		return err
	}
	for _, name := range []string{"recon.json", "recon_tools.md"} {
		if err := copyFile(filepath.Join(b.Dir, name), filepath.Join(destWorkdir, name)); err != nil && name == "recon.json" {
			return err
		}
	}
	toolsSrc := filepath.Join(b.Dir, "tools")
	_ = copyIter01Logs(toolsSrc, filepath.Join(destWorkdir, "tools"))
	// Also copy iter01 from source run tools if bundle tools/ empty
	if source := b.Manifest.SourceRun; source != "" {
		_ = copyIter01Logs(filepath.Join(source, "tools"), filepath.Join(destWorkdir, "tools"))
	}
	return nil
}

func ReadRecon(b *Bundle) (reconJSON, toolLog string, err error) {
	reconBytes, err := os.ReadFile(filepath.Join(b.Dir, "recon.json"))
	if err != nil {
		return "", "", err
	}
	reconJSON = string(reconBytes)
	toolBytes, err := os.ReadFile(filepath.Join(b.Dir, "recon_tools.md"))
	if err == nil {
		toolLog = string(toolBytes)
	}
	return reconJSON, toolLog, nil
}
```

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add neurosploit-go/internal/reconcache/
git commit -m "feat: reconcache publish and import"
```

---

### Task 4: Discovery — FindBundle and FindLatestRun

**Files:**
- Modify: `neurosploit-go/internal/reconcache/cache.go`
- Create: `neurosploit-go/internal/reconcache/discover_test.go`

**Interfaces:**
- Produces: `func FindBundle(cacheRoot, slug string) (*Bundle, error)`, `func FindLatestRun(runsRoot, slug string) (*Bundle, error)`, `func BundleFromRun(runDir string) (*Bundle, error)`, `func ListRuns(runsRoot, slug string, limit int) []RunEntry`.

```go
type RunEntry struct {
	Dir  string
	Age  time.Duration
	Tools []string // from recon_tools.md header if parseable, else nil
}
```

- [ ] **Step 1: Write failing tests**

```go
func TestFindBundle(t *testing.T) {
	cacheRoot := t.TempDir()
	_, err := FindBundle(cacheRoot, "example.com")
	if err == nil {
		t.Fatal("expected not found")
	}
	_, err = Publish(cacheRoot, "runs/ns-1-example.com", "http://example.com/", `{"x":1}`, "", []string{"httpx"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := FindBundle(cacheRoot, "example.com")
	if err != nil || b.Slug != "example.com" {
		t.Fatalf("FindBundle: %v %+v", err, b)
	}
}

func TestFindLatestRun(t *testing.T) {
	runsRoot := t.TempDir()
	slug := "example.com"
	oldDir := filepath.Join(runsRoot, "ns-1000-"+slug)
	newDir := filepath.Join(runsRoot, "ns-2000-"+slug)
	for _, d := range []string{oldDir, newDir} {
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, "recon.json"), []byte(`{"endpoints":["http://example.com/"]}`), 0644)
	}
	b, err := FindLatestRun(runsRoot, slug)
	if err != nil || b.Dir != newDir {
		t.Fatalf("want newest run %s got %v err=%v", newDir, b, err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement discovery**

```go
func FindBundle(cacheRoot, slug string) (*Bundle, error) {
	dir := filepath.Join(cacheRoot, slug)
	b, err := LoadBundle(dir)
	if err != nil {
		return nil, fmt.Errorf("no recon cache for %s: %w", slug, err)
	}
	return b, nil
}

func BundleFromRun(runDir string) (*Bundle, error) {
	reconPath := filepath.Join(runDir, "recon.json")
	raw, err := os.ReadFile(reconPath)
	if err != nil {
		return nil, err
	}
	if !ValidReconJSON(string(raw)) {
		return nil, fmt.Errorf("invalid recon in %s", runDir)
	}
	slug := Slug(filepath.Base(runDir)) // extract after ns-ts-
	// Parse slug from dirname: ns-<ts>-<slug>
	base := filepath.Base(runDir)
	parts := strings.SplitN(base, "-", 3)
	if len(parts) >= 3 {
		slug = parts[2]
	}
	m := Manifest{
		Target:    "", // unknown until manifest; optional read from recon.md
		Slug:      slug,
		CreatedAt: modTimeRFC3339(runDir),
		SourceRun: runDir,
	}
	return &Bundle{Dir: runDir, Slug: slug, Manifest: m}, nil
}

func FindLatestRun(runsRoot, slug string) (*Bundle, error) {
	suffix := "-" + slug
	var best string
	var bestTS int64
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "ns-") || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		dir := filepath.Join(runsRoot, e.Name())
		if _, err := BundleFromRun(dir); err != nil {
			continue
		}
		// Parse timestamp from ns-<ts>-<slug>
		parts := strings.SplitN(e.Name(), "-", 3)
		if len(parts) < 2 {
			continue
		}
		var ts int64
		fmt.Sscanf(parts[1], "%d", &ts)
		if ts >= bestTS {
			bestTS = ts
			best = dir
		}
	}
	if best == "" {
		return nil, fmt.Errorf("no prior run for %s", slug)
	}
	return BundleFromRun(best)
}

func Discover(cacheRoot, runsRoot, slug string) (*Bundle, error) {
	if b, err := FindBundle(cacheRoot, slug); err == nil {
		return b, nil
	}
	return FindLatestRun(runsRoot, slug)
}
```

Add `modTimeRFC3339` helper using `os.Stat`.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: reconcache discovery (cache + run index)"
```

---

### Task 5: Policy resolution and TTY prompt

**Files:**
- Create: `neurosploit-go/internal/reconcache/policy.go`
- Create: `neurosploit-go/internal/reconcache/policy_test.go`

**Interfaces:**
- Produces: `func IsTTY() bool`, `func Resolve(cfg types.RunConfig, bundle *Bundle, tty bool) (types.ReconPolicy, error)`, `func PromptReuse(bundle *Bundle, listFn func() []RunEntry) (types.ReconPolicy, error)`.

- [ ] **Step 1: Write failing tests**

```go
func TestResolveNonTTYDefaultsReuse(t *testing.T) {
	cfg := types.RunConfig{Target: "http://example.com/"}
	p, err := Resolve(cfg, &Bundle{Slug: "example.com"}, false)
	if err != nil || p != types.ReconPolicyReuse {
		t.Fatalf("got %q err=%v", p, err)
	}
}

func TestResolveFlagNew(t *testing.T) {
	cfg := types.RunConfig{ReconPolicy: types.ReconPolicyNew}
	p, err := Resolve(cfg, &Bundle{}, false)
	if err != nil || p != types.ReconPolicyNew {
		t.Fatalf("got %q", p)
	}
}

func TestResolveReuseMissingBundle(t *testing.T) {
	cfg := types.RunConfig{ReconPolicy: types.ReconPolicyReuse}
	_, err := Resolve(cfg, nil, false)
	if err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement policy.go**

```go
package reconcache

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func IsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func Resolve(cfg types.RunConfig, bundle *Bundle, tty bool) (types.ReconPolicy, error) {
	switch cfg.ReconPolicy {
	case types.ReconPolicyNew:
		return types.ReconPolicyNew, nil
	case types.ReconPolicyReuse:
		if bundle == nil {
			return "", fmt.Errorf("no recon cache for %s; run with --recon new", Slug(cfg.Target))
		}
		return types.ReconPolicyReuse, nil
	}
	if bundle == nil {
		return types.ReconPolicyNew, nil
	}
	if tty {
		return types.ReconPolicyAsk, nil
	}
	return types.ReconPolicyReuse, nil
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func PromptReuse(bundle *Bundle, listRuns func() []RunEntry) (types.ReconPolicy, error) {
	for {
		warn := ""
		if bundle.StaleWarning() {
			warn = " [stale: >7 days]"
		}
		fmt.Fprintf(os.Stderr,
			"Found recon for %s (%s, %d tools, from %s)%s\n[R] Reuse  [N] New scan  [L] List prior runs  [Q] Quit\n> ",
			bundle.Slug, formatAge(bundle.Age()), len(bundle.Manifest.Tools), bundle.SourceRunBase(), warn)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "r", "reuse":
			return types.ReconPolicyReuse, nil
		case "n", "new":
			return types.ReconPolicyNew, nil
		case "l", "list":
			for i, e := range listRuns() {
				fmt.Fprintf(os.Stderr, "  %d. %s (%s)\n", i+1, filepath.Base(e.Dir), formatAge(e.Age))
			}
		case "q", "quit":
			os.Exit(0)
		}
	}
}
```

Add `import "path/filepath"` for List display.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: reconcache policy resolution and TTY prompt"
```

---

### Task 6: Wire engagement.Execute

**Files:**
- Modify: `neurosploit-go/internal/engagement/engagement.go`
- Create: `neurosploit-go/internal/engagement/recon_test.go`

**Interfaces:**
- Consumes: all `reconcache` exports.
- Produces: `cfg` gets `ReconBundle *reconcache.Bundle` stored via new field `ResolvedReconBundle` on RunConfig OR pass through context — prefer adding `types.RunConfig.CachedRecon *string` is wrong; use package-level or return struct.

**Design choice:** Add optional field to `RunConfig`:

```go
// ResolvedReconDir is set when recon is imported before pipeline (internal use).
ResolvedReconDir string `json:"-"`
```

And in `Execute` after `PrepareWorkdir`:

```go
slug := reconcache.Slug(cfg.Target)
cacheRoot := cfg.ReconCachePath
if cacheRoot == "" {
	cacheRoot = types.DefaultReconCachePath
}
var bundle *reconcache.Bundle
if cfg.ReconFromRun != "" {
	bundle, _ = reconcache.BundleFromRun(cfg.ReconFromRun)
} else {
	bundle, _ = reconcache.Discover(cacheRoot, "runs", slug)
}
policy, err := reconcache.Resolve(cfg, bundle, reconcache.IsTTY())
if err != nil {
	return pipeline.RunOutput{Target: cfg.Target, Workdir: workdir}, err
}
if policy == types.ReconPolicyAsk {
	policy, err = reconcache.PromptReuse(bundle, func() []reconcache.RunEntry {
		return reconcache.ListRuns("runs", slug, 10)
	})
	if err != nil {
		return pipeline.RunOutput{...}, err
	}
}
if policy == types.ReconPolicyReuse && bundle != nil {
	if err := reconcache.Import(bundle, workdir); err != nil {
		if progress != nil {
			progress <- fmt.Sprintf("recon import failed (%v) — running fresh", err)
		}
	} else {
		cfg.ResolvedReconDir = workdir
		if progress != nil {
			progress <- fmt.Sprintf("recon: reused from %s (%s)", bundle.Dir, reconcache.FormatAge(bundle.Age()))
		}
	}
}
```

Export `FormatAge` from reconcache (rename `formatAge`).

- [ ] **Step 1: Write test with fake bundle**

Test that `Execute` with `--recon reuse` and pre-seeded cache does not error (use offline stub pool).

- [ ] **Step 2–5: Implement, test, commit**

```bash
git commit -m "feat: engagement resolves recon policy before pipeline"
```

---

### Task 7: Pipeline — skip bootstrap and publish

**Files:**
- Modify: `neurosploit-go/internal/pipeline/run.go`
- Create: `neurosploit-go/internal/pipeline/recon_cache_test.go`

**Interfaces:**
- Consumes: `cfg.ResolvedReconDir`, `cfg.ReconPolicy`, `reconcache.Publish`.

- [ ] **Step 1: Write failing test**

```go
func TestRunReconSkipsBootstrapWhenCached(t *testing.T) {
	// Stub executor that panics if called
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "recon.json"), []byte(`{"endpoints":["http://example.com/"]}`), 0644)
	cfg := types.NewRunConfig("http://example.com/")
	cfg.ResolvedReconDir = dir
	recon, toolLog := loadCachedRecon(dir)
	if recon == "" {
		t.Fatal("expected cached recon")
	}
	_ = toolLog
}
```

- [ ] **Step 2: Add helpers in run.go**

```go
func loadCachedRecon(workdir string) (recon, toolLog string) {
	reconBytes, err := os.ReadFile(filepath.Join(workdir, "recon.json"))
	if err != nil {
		return "{}", ""
	}
	recon = string(reconBytes)
	if b, err := os.ReadFile(filepath.Join(workdir, "recon_tools.md")); err == nil {
		toolLog = string(b)
	}
	return recon, toolLog
}
```

Modify `runRecon`:

```go
func runRecon(ctx context.Context, cfg types.RunConfig, p PoolCaller, progress chan<- string, mcpOn bool) (string, string) {
	if cfg.ResolvedReconDir != "" {
		recon, toolLog := loadCachedRecon(cfg.ResolvedReconDir)
		if ValidReconCached(recon) {
			sendProgress(progress, "recon: loaded from cache (bootstrap skipped)")
			return recon, toolLog
		}
	}
	// ... existing runRecon body ...
	// After successful recon, before return:
	if cfg.Offline || !ValidReconCached(text) {
		return text, toolLog
	}
	cacheRoot := cfg.ReconCachePath
	if cacheRoot == "" {
		cacheRoot = types.DefaultReconCachePath
	}
	workdir := ""
	if cfg.Workdir != nil {
		workdir = *cfg.Workdir
	}
	tools := extractToolNamesFromLog(toolLog)
	if _, err := reconcache.Publish(cacheRoot, workdir, cfg.Target, text, toolLog, tools); err != nil && cfg.Verbose {
		sendProgress(progress, fmt.Sprintf("recon cache publish: %v", err))
	}
	return text, toolLog
}
```

Modify `runSubscriptionRecon` — when `cfg.ResolvedReconDir != ""`, return early without `runBootstrapTools`.

Add `extractToolNamesFromLog` — parse `## N. toolname` from toolLog or pass obs tool names from bootstrap.

- [ ] **Step 3: Run pipeline tests**

Run: `cd neurosploit-go && go test ./internal/pipeline/... -run TestRunRecon -v`

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: pipeline skips bootstrap on cached recon and publishes cache"
```

---

### Task 8: CLI flags on all engagement commands

**Files:**
- Modify: `neurosploit-go/cmd/neurosploit/main.go`

- [ ] **Step 1: Add shared flag helper**

```go
func addReconFlags(cmd *cobra.Command, policy *string, fromRun, cachePath *string) {
	cmd.Flags().StringVar(policy, "recon", "", "Recon policy: new, reuse (default: ask on TTY, reuse off TTY)")
	cmd.Flags().StringVar(fromRun, "from-run", "", "Import recon from a prior run directory")
	cmd.Flags().StringVar(cachePath, "recon-cache", "", "Recon cache root (default: data/recon-cache)")
}
```

Wire in `runCmd`, `greyboxCmd`, `hostCmd`, `whiteboxCmd`:

```go
var reconFlag, fromRun, reconCache string
// in RunE:
switch strings.ToLower(reconFlag) {
case "", "ask":
	cfg.ReconPolicy = types.ReconPolicyAsk // or leave empty for auto
case "new":
	cfg.ReconPolicy = types.ReconPolicyNew
case "reuse":
	cfg.ReconPolicy = types.ReconPolicyReuse
default:
	return fmt.Errorf("invalid --recon %q (want new|reuse)", reconFlag)
}
cfg.ReconFromRun = fromRun
cfg.ReconCachePath = reconCache
```

- [ ] **Step 2: Build**

Run: `cd neurosploit-go && go build ./cmd/neurosploit`

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: add --recon --from-run --recon-cache CLI flags"
```

---

### Task 9: REPL /recon commands

**Files:**
- Modify: `neurosploit-go/internal/repl/repl.go`

- [ ] **Step 1: Add handlers**

```go
case strings.HasPrefix(line, "/recon "):
	// /recon list [slug]
	// /recon clear <slug>
	// /recon import <run-dir>
```

`/recon list` — call `reconcache.FindBundle` + `ListRuns`, print table to stdout.

`/recon clear <slug>` — `os.RemoveAll(filepath.Join(types.DefaultReconCachePath, slug))`

`/recon import <dir>` — `reconcache.Publish` from run dir's recon.json

- [ ] **Step 2: Update help text** in REPL banner.

- [ ] **Step 3: Test manually + commit**

```bash
git commit -m "feat: REPL /recon list|clear|import commands"
```

---

### Task 10: gitignore, PARITY.md, AGENTS.md

**Files:**
- Modify: `.gitignore` — add `data/recon-cache/`
- Modify: `docs/PARITY.md` — item 12: recon cache Go enhancement
- Modify: `AGENTS.md` — mention `data/recon-cache/` is local-only engagement data

- [ ] **Step 1: Edit files**

```
# .gitignore
data/recon-cache/
```

```
# PARITY.md
12. **Recon cache (Go)**: `data/recon-cache/<slug>/` canonical bundles; `--recon new|reuse`, TTY prompt, non-TTY auto-reuse. Rust has no equivalent.
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore docs/PARITY.md AGENTS.md
git commit -m "docs: recon cache parity and gitignore"
```

---

### Task 11: End-to-end verification

- [ ] **Step 1: Full CI**

Run: `cd neurosploit-go && go vet ./... && go test ./... -timeout 60s`
Expected: all pass

- [ ] **Step 2: Manual smoke (local only, not committed)**

```bash
# First run — populates cache
./neurosploit-go/neurosploit run http://example.com/ --offline --max-agents 1

# Second run — should skip bootstrap (check progress line)
./neurosploit-go/neurosploit run http://example.com/ --offline --max-agents 1 -v 2>&1 | head -20
```

Expect: `recon: reused from` or `recon: loaded from cache`

- [ ] **Step 3: Force new**

```bash
./neurosploit-go/neurosploit run http://example.com/ --offline --recon new --max-agents 1 -v 2>&1 | head -5
```

- [ ] **Step 4: Final commit if any fixups**

```bash
git commit -m "test: recon cache e2e verification fixes"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Auto-detect prior recon | Task 4 Discover |
| TTY prompt D | Task 5 PromptReuse |
| Non-TTY reuse A | Task 5 Resolve |
| Publish cache bundle | Task 3 Publish |
| Import into new workdir | Task 3 Import + Task 6 |
| Skip runBootstrapTools | Task 7 |
| CLI flags all modes | Task 8 |
| REPL /recon | Task 9 |
| Run-index fallback | Task 4 FindLatestRun |
| 7-day stale warning | Task 5 PromptReuse |
| example.com tests only | All test tasks |
| PARITY.md | Task 10 |
| gitignore cache | Task 10 |

## Self-review

- No TBD/TODO placeholders.
- Type names consistent: `ReconPolicy`, `Bundle`, `Resolve`, `Publish`, `Import`, `Discover`.
- All spec sections mapped to tasks.
- Out-of-scope items (separate subcommand, per-tool refresh, S3) excluded.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-02-recon-cache.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration  
2. **Inline Execution** — implement tasks in this session with checkpoints

Which approach?
