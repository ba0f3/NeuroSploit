# Greybox & Host Mode Parity — Go Harness

- **Date:** 2026-07-01
- **Topic:** Wire `greybox` and `host` modes end-to-end in `neurosploit-go/` to match Rust harness and the 2026-06-30 port design spec.
- **Status:** Approved (brainstorming complete, ready for implementation planning)
- **Parent spec:** [`2026-06-30-neurosploit-go-port-design.md`](2026-06-30-neurosploit-go-port-design.md)

## Problem

`pipeline.RunGreybox` and `pipeline.RunHost` are implemented in Go, and
`engagement.Execute` routes to them — but users cannot reach these modes:

- CLI has no `greybox` or `host` subcommands (`main.go` only registers `run`,
  `whitebox`, `tui`, `agents`, `models`).
- REPL always calls `engagement.Execute(..., "run", ...)`, ignoring `/repo`.
- TUI hardcodes black-box mode; no `--repo` flag.
- `applyCreds` only sets `AuthHeader`; Rust also injects SSH/AD host
  instructions and performs auto-login.
- `resolveSource` (GitHub clone / `owner/repo` shorthand) is missing.
- No offline tests for greybox or host; `docs/PARITY.md` overstates pipeline
  parity.

## Goal

Full surface parity for greybox and host modes:

1. CLI subcommands with spec-correct flags.
2. REPL mode detection + `/creds` command.
3. TUI `--repo` greybox support.
4. Shared `ApplyCreds`, `DetectMode`, `NormalizeURL`, `ResolveSource`.
5. Minimal `integrations` package for authed Git clone.
6. Offline integration tests + corrected `docs/PARITY.md`.

## Out of scope

- `pr`, `watch`, `integrations` CLI subcommands (separate work).
- Full `internal/integrations` port (Jira, PR comments, commit watch).
- Global REPL parity (`/continue`, `/attach`, run history checkpointing).
- Changes to `RunGreybox` / `RunHost` pipeline orchestration (already ported).

## Approach

**Approach B — shared engagement layer (selected).**

Extract testable helpers in `internal/engagement`, `internal/source`, and a
minimal `internal/integrations`. CLI, REPL, and TUI become thin callers.

Alternatives rejected:

- **A (patch in place):** duplicates mode/creds/URL logic across three entry
  points; harder to test.
- **C (phased PRs):** same code as B but split across reviews; user requested
  full parity in one pass.

## Section 1 — Shared helpers

### `engagement.ApplyCreds(ctx, cfg *RunConfig, path string) error`

Port Rust `apply_creds` from `neurosploit-rs/app/src/main.rs`:

1. If `path` empty, return nil.
2. Load via `creds.Load(path)`; log warning if nil.
3. If `cfg.Auth` unset, set from `cr.AuthHeader()`.
4. If `cr.HostInstruction()` non-nil, prepend to `cfg.Instructions`
   (`"{hi}\n{existing}"`).
5. If `cfg.Auth` still unset and `cr.Login` present:
   - Call `creds.DoLogin(ctx, cr.Login)`.
   - On success: set `cfg.Auth`, log note.
   - On failure: prepend `cr.LoginInstruction()` to instructions; log error.

Print status lines to stderr (match Rust UX: `[*] loaded credentials`,
`[*] host credentials loaded`, etc.).

Replace the stub `applyCreds` in `cmd/neurosploit/main.go`; call from CLI,
REPL, and TUI.

### `engagement.DetectMode(repo, target string, cr *creds.Creds) (mode string, err error)`

| Condition | Mode |
|---|---|
| `repo != ""` && `target != ""` | `greybox` |
| `repo != ""` && `target == ""` | `whitebox` |
| `repo == ""` && `target != ""` && host creds && non-HTTP target | `host` |
| `repo == ""` && `target != ""` | `run` (black-box) |
| both empty | error: `"set /target and/or /repo first"` |

**Host creds:** `cr != nil && cr.HostInstruction() != nil`.

**Non-HTTP target:** does not start with `http://` or `https://`.

**REPL host routing:** Rust REPL help documents host mode (`/target <ip> +
/creds`) but `start_background` never routes to `Mode::Host`. Go implements
what the docs promise — a deliberate improvement noted in `PARITY.md`.

### `engagement.NormalizeURL(url string) string`

If `url` lacks `http://` or `https://` prefix, prepend `https://`. Used for
greybox `--url` and TUI target.

### `source.Resolve(base, arg string) (string, error)`

Port Rust `resolve_source` from `neurosploit-rs/app/src/main.rs`:

1. Classify `arg`:
   - Local path if it exists on disk.
   - Git URL if starts with `http://`, `https://`, `git@`, `ssh://`, or ends
     with `.git`.
   - GitHub shorthand if exactly one `/`, no scheme, not a local path, chars
     in `[a-zA-Z0-9._-/]`.
2. Shorthand → `https://github.com/{arg}`.
3. Clone destination: `{base}/repos/{sanitized-name}` (reuse
   `engagement.SanitizeTarget` logic for name).
4. Cache hit: if `{dest}/.git` exists, return `dest` (print cache hit).
5. Clone: shallow `git clone --depth 1` via `os/exec`. Use
   `integrations.Load(repl.ProjDir()).AuthedCloneURL(url)` for token injection.
6. On clone failure: remove partial `dest`, return error.

### `internal/integrations` (minimal)

Port only what `source.Resolve` needs:

- `Integrations{Github, Gitlab}` structs with JSON tags matching Rust schema.
- `Load(dir)` from `{dir}/integrations.json` (default empty).
- `AuthedCloneURL(url)` — GitHub `x-access-token:{token}@github.com/...` and
  GitLab `oauth2:{token}@{host}/...` when integration enabled and env var set.
- Secrets: store env var **names** in JSON, read values from environment at
  runtime (same policy as Rust).

No Jira, no HTTP API calls, no `Save` CLI — just Load + AuthedCloneURL.

## Section 2 — CLI

Register `greyboxCmd()` and `hostCmd()` in `rootCmd().AddCommand(...)`.

### `greybox <repo> --url <app>`

| Flag | Default | Notes |
|---|---|---|
| `--url` | (required) | Live app URL |
| `--model` | `anthropic:claude-opus-4-8` | repeatable |
| `--max-agents` | 0 (unlimited) | |
| `--vote-n` | 3 | |
| `--offline` | false | stub pool |
| `--subscription` | false | |
| `--mcp` | false | |
| `--creds` | | creds.yaml |
| `--focus` | | operator instructions |
| `-v` / `--verbose` | false | |

Flow:

```
repoPath, err := source.Resolve(base, args[0])
cfg := NewRunConfig(NormalizeURL(--url))
cfg.Repo = &repoPath
// set models, flags...
ApplyCreds(ctx, &cfg, --creds)
runEngagement(ctx, cfg, ..., "greybox", stubOrNil)
```

### `host <target>`

| Flag | Default | Notes |
|---|---|---|
| `--model` | `anthropic:claude-opus-4-8` | repeatable |
| `--creds` | | ssh/windows blocks |
| `--focus` | | |
| `--max-agents` | 0 | |
| `--vote-n` | 3 | |
| `--offline` | false | |
| `--subscription` | false | |
| `-v` / `--verbose` | false | |

No `--mcp` flag (matches Rust: host engagement passes `mcp=false`).

Flow:

```
cfg := NewRunConfig(args[0])  // IP/hostname as-is, no URL normalize
ApplyCreds(ctx, &cfg, --creds)
runEngagement(ctx, cfg, ..., "host", stubOrNil)
```

Also refactor existing `runCmd` / `whiteboxCmd` to call `engagement.ApplyCreds`
instead of the inline stub.

## Section 3 — REPL

### Session changes

Add `CredsPath string` to `repl.Session`.

### New command: `/creds <file.yaml>`

Set `s.CredsPath`; no arg → show current path.

### Mode detection in `backgroundRun`

```go
cr := creds.Load(s.CredsPath) // or nil
mode, err := engagement.DetectMode(s.Repo, s.Target, cr)
cfg := s.RunConfig()
if s.Repo != "" { cfg.Repo = &s.Repo }
engagement.ApplyCreds(ctx, &cfg, s.CredsPath)
engagement.Execute(ctx, s.Base, cfg, mode, s.MCP, stub, progress)
```

Set `s.live.Mode` to human-readable string (`greybox`, `white-box`, `black-box`,
`host/infra`).

### `/show` update

Display inferred mode (same table as Rust `show()`):

```
repo + target → greybox (code + live)
repo only     → white-box (code)
target only   → black-box (live) or host/infra when host creds
neither       → (set /target and/or /repo)
```

Also show `creds:` line.

### Help text

Add `/creds`, mode summary line, update `/repo` description.

## Section 4 — TUI

Extend `tuiCmd()`:

| Flag | Notes |
|---|---|
| `--repo` | optional; triggers greybox |
| `--creds` | creds.yaml |
| `--focus` | operator instructions |

Flow:

```
mode := "run"
if --repo != "" {
    mode = "greybox"
    repoPath, _ := source.Resolve(base, --repo)
    cfg.Repo = &repoPath
}
cfg.Target = NormalizeURL(args[0])
ApplyCreds(ctx, &cfg, --creds)
tui.Run(base, cfg, mode, mcp)
```

`internal/tui/mission.go` already accepts `mode string` and passes it to
`engagement.Execute` — no model changes needed beyond flag wiring in `main.go`.

## Section 5 — Progress line parity

In `pipeline.parallelExploit`, after extracting findings:

```go
for _, c := range f {
    sendProgress(progress, fmt.Sprintf("finding: [%s] %s @ %s", ...))
    if b, err := json.Marshal(c); err == nil {
        sendProgress(progress, "finding_json: "+string(b))
    }
}
```

When `builder.host == true`, use `test` instead of `exploit` in the progress
line prefix (match Rust host wording).

## Section 6 — Testing

| Test file | Test | Asserts |
|---|---|---|
| `engagement/creds_test.go` | `TestApplyCredsHostInstruction` | SSH block prepends instructions |
| `engagement/creds_test.go` | `TestApplyCredsAutoLogin` | httptest login → cfg.Auth |
| `engagement/mode_test.go` | `TestDetectMode` | table-driven mode matrix |
| `source/resolve_test.go` | `TestResolveLocalPath` | existing dir returned as-is |
| `source/resolve_test.go` | `TestClassifySource` | URL vs shorthand vs local |
| `integrations/integrations_test.go` | `TestAuthedCloneURL` | token injection when enabled |
| `pipeline/pipeline_test.go` | `TestRunGreyboxOffline` | workdir, no panic, agents ran |
| `pipeline/pipeline_test.go` | `TestRunHostOffline` | workdir, recon `{}`, no panic |
| `repl/repl_test.go` | `TestDetectModeFromSession` | repo+target → greybox via helper |

Greybox offline stub: return `[]` for exploit JSON (no live findings expected).
Host offline stub: return `[]` for exploit; recon `{}`.

Run gate: `go vet ./... && go test ./... -timeout 30s`.

## Section 7 — PARITY.md updates

Split the pipeline row:

| Item | Status |
|---|---|
| `RunGreybox` / `RunHost` pipeline logic | ✅ (pre-existing) |
| CLI `greybox` / `host` subcommands | 🔲 → ✅ after this work |
| REPL mode detection + `/creds` | 🔲 → ✅ |
| TUI `--repo` greybox | 🔲 → ✅ |
| `applyCreds` full parity | 🔲 → ✅ |
| `resolveSource` | 🔲 → ✅ |
| Greybox/host offline tests | 🔲 → ✅ |

Document deviations:

- Go host recon uses tool-loop when tools registry present (intentional Go
  extension).
- Go REPL routes to host mode when SSH/Win creds + non-HTTP target (closes Rust
  doc/code gap).

## File touch list

| Path | Action |
|---|---|
| `internal/engagement/creds.go` | new: ApplyCreds, DetectMode, NormalizeURL |
| `internal/engagement/creds_test.go` | new |
| `internal/engagement/mode_test.go` | new |
| `internal/source/resolve.go` | new |
| `internal/source/resolve_test.go` | new |
| `internal/integrations/integrations.go` | new (minimal) |
| `internal/integrations/integrations_test.go` | new |
| `cmd/neurosploit/main.go` | greyboxCmd, hostCmd, tui flags, ApplyCreds delegate |
| `internal/repl/repl.go` | /creds, mode detection, /show, help |
| `internal/repl/repl_test.go` | mode/creds tests |
| `internal/pipeline/run.go` | finding_json + host progress wording |
| `internal/pipeline/pipeline_test.go` | greybox/host offline tests |
| `docs/PARITY.md` | corrected status rows |

No changes to `neurosploit-rs/` or `agents_md/`.

## Success criteria

1. `neurosploit greybox /tmp/DVWA --url http://localhost:8080/ --offline`
   completes and writes artifacts under `runs/ns-*`.
2. `neurosploit host 10.0.0.10 --creds creds.example.yaml --offline`
   completes and selects infra agents.
3. REPL: `/repo /tmp/DVWA` + `/target http://localhost:8080/` + `/run` invokes
   greybox (progress line starts with `GREYBOX ·`).
4. `neurosploit tui http://localhost:8080/ --repo /tmp/DVWA --offline` runs
   greybox mode.
5. All tests pass; `docs/PARITY.md` reflects accurate status.
