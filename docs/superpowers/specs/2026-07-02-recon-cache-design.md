# Recon Cache and Reuse Design

## Goal

Eliminate redundant pre-recon tool runs when re-testing the same target. Today
every `neurosploit run` creates a fresh workdir and always executes the full
subscription bootstrap stack (httpx, whatweb, katana, nmap, nuclei, gau,
subfinder) — often several minutes before exploitation begins. Prior recon
artifacts in `runs/ns-*-<target>/` are write-only and never consulted.

The harness should:

1. **Auto-detect** prior recon for the same target.
2. **Ask interactively** (TTY) whether to reuse or rescan.
3. **Default to reuse** in non-interactive mode (scripts, CI).
4. **Publish** a canonical recon bundle per target for sharing and inspection.
5. Preserve per-run workdirs (`runs/ns-<ts>-<target>/`) for findings,
   transcripts, and tool logs from exploitation.

## Current Problem

| Symptom | Cause |
|---------|-------|
| Nuclei + full bootstrap re-run on every engagement | `runSubscriptionRecon` always calls `runBootstrapTools` |
| No cross-run sharing | `PrepareWorkdir` always creates a new timestamped dir |
| Recon artifacts orphaned | `recon.json`, `recon_tools.md`, `tools/iter01-*` exist but are never read back |
| Iteration cost | Tuning models/agents/focus on the same target repeats ~5+ min recon |

Concrete user workflow (approved):

- **Interactive (D):** auto-detect prior recon, prompt each start.
- **Non-interactive (A):** default to reuse; override with `--recon new`.

## Approach

**Target recon cache** (recommended over run-index-only or split subcommand):

- After a successful bootstrap recon, **publish** a bundle to
  `data/recon-cache/<slug>/`.
- On engagement start, **resolve** recon policy (ask / reuse / new).
- If reusing, **import** bundle into the new run workdir and **skip**
  `runBootstrapTools`.
- Fall back to scanning `runs/ns-*-<slug>/` when no cache entry exists yet.

This keeps one `run` command, adds an explicit shareable cache, and reuses
existing artifact formats.

## Recon Bundle Layout

```
data/recon-cache/<slug>/
├── manifest.json      # metadata + provenance
├── recon.json         # synthesized attack-surface JSON
├── recon_tools.md     # formatted bootstrap tool observations
└── tools/             # iter01 bootstrap logs (copied from source run)
    ├── iter01-run001-httpx.log
    └── ...
```

### manifest.json

```json
{
  "target": "http://example.com/",
  "slug": "example.com",
  "created_at": "2026-07-02T12:34:56Z",
  "source_run": "runs/ns-1782961579-example.com",
  "tools": ["httpx", "whatweb", "katana", "nmap", "nuclei", "gau", "subfinder"],
  "recon_hash": "sha256:abc123..."
}
```

| Field | Purpose |
|-------|---------|
| `target` | Original URL as provided at recon time |
| `slug` | Filesystem key from `SanitizeTarget(target)` |
| `created_at` | RFC3339 timestamp for age display and staleness warnings |
| `source_run` | Provenance — which run produced this bundle |
| `tools` | Bootstrap tools that ran (for prompt display) |
| `recon_hash` | SHA256 of `recon.json` for integrity checks |

**Valid bundle:** `manifest.json` parses, `recon.json` exists, is non-empty, and
is not `{}` or whitespace-only.

**Invalid bundle:** treat as missing; fall back to fresh recon or run-index
scan.

## Target Matching

Reuse existing `engagement.SanitizeTarget()`:

- `http://example.com`, `https://example.com/`, and `example.com` → slug
  `example.com`.
- Slug collision = same target for cache purposes.

**Discovery order:**

1. `data/recon-cache/<slug>/manifest.json` (if valid bundle).
2. Fallback: newest `runs/ns-*-<slug>/` containing valid `recon.json`.
3. None found → fresh recon (no prompt).

**Staleness:** bundles older than **7 days** show a warning in the interactive
prompt but remain reusable. No automatic expiry — user chooses reuse or new scan.

## CLI and REPL UX

### Flags

Apply to all engagement commands: `run`, `greybox`, `host`, `whitebox`.

| Flag | Behavior |
|------|----------|
| *(default, TTY)* | Prompt if valid bundle or prior run found |
| *(default, no TTY)* | Auto-reuse latest valid bundle |
| `--recon new` | Force fresh bootstrap scan; publish updated cache on success |
| `--recon reuse` | Force reuse; exit 1 if no valid bundle or prior run |
| `--from-run <dir>` | Import from a specific run directory (bypass cache lookup) |
| `--recon-cache <path>` | Override cache root (default: `data/recon-cache`) |

Add `ReconPolicy`, `ReconCachePath`, and `ReconFromRun` fields to
`types.RunConfig`.

### Interactive prompt (TTY only)

When a valid bundle or prior run is found:

```
Found recon for example.com (2h ago, 7 tools, from ns-1782961579-example.com)
[R] Reuse  [N] New scan  [L] List prior runs  [Q] Quit
>
```

| Key | Action |
|-----|--------|
| R / Enter | Import bundle, skip bootstrap |
| N | Fresh bootstrap scan |
| L | List up to 10 prior runs for slug with age; re-prompt |
| Q | Exit 0 |

Non-TTY: skip prompt; apply default reuse (flag `--recon new` overrides).

### REPL commands

| Command | Action |
|---------|--------|
| `/recon list [slug]` | List cached bundles and recent runs |
| `/recon clear <slug>` | Delete cache entry for slug |
| `/recon import <run-dir>` | Manually publish bundle from a run dir |

## Pipeline Integration

```
Execute()
  → PrepareWorkdir()              # always create new runs/ns-<ts>-<slug>/
  → resolveReconPolicy(cfg)       # ask | reuse | new (from flags + TTY)
  → if reuse:
        importReconBundle(cfg)    # copy into new workdir
        runReconFromCache(...)    # return cached recon.json + recon_tools.md
        log: "recon: reused from data/recon-cache/example.com (2h ago)"
    else:
        runRecon(...)             # existing path
        publishReconBundle(...)   # on success, update cache
  → selectAgents → exploit → validate → chain → finish
```

### Changes to runRecon / runSubscriptionRecon

- Extract `loadCachedRecon(workdir, bundle) (reconJSON, toolLog string)`.
- When policy is `reuse`, `runSubscriptionRecon` **does not** call
  `runBootstrapTools`. Cached `recon.json` is returned directly; cached
  `recon_tools.md` becomes `toolLog`.
- When policy is `new`, behavior unchanged; call `publishReconBundle` after
  successful recon before agent selection.

### Offline mode

- Reuse from cache allowed (`--recon reuse` or default non-TTY).
- `--recon new` in offline mode uses existing stub recon (`{}`); do not publish
  empty bundles.

## New Package: internal/reconcache

| Function | Responsibility |
|----------|----------------|
| `Slug(target string) string` | Delegate to `SanitizeTarget` |
| `FindBundle(cacheRoot, slug string) (*Bundle, error)` | Cache lookup + validation |
| `FindLatestRun(runsRoot, slug string) (*Bundle, error)` | Run-index fallback |
| `Publish(cacheRoot, sourceRun, target, recon, toolLog string) error` | Write/update bundle |
| `Import(bundle, destWorkdir string) error` | Copy files into new run |
| `ListRuns(runsRoot, slug string, limit int) []RunEntry` | For prompt `[L]` |
| `ResolvePolicy(cfg, bundle *Bundle, tty bool) (Policy, error)` | Flags + prompt |
| `PromptReuse(bundle *Bundle) (Policy, error)` | TTY interactive |

Keep filesystem I/O in this package; pipeline calls it from `runRecon` and
`engagement.Execute`.

## Error Handling

| Case | Behavior |
|------|----------|
| No prior recon | Run fresh silently (no prompt) |
| Corrupt cache (bad JSON, missing files) | Warn to stderr; fall back to fresh recon |
| `--recon reuse` but nothing found | Exit 1: `no recon cache for <slug>; run with --recon new` |
| `--from-run` path invalid | Exit 1 with path error |
| Empty recon `{}` after fresh scan | Do not publish; warn |
| Concurrent runs same target | Last publish wins; each run keeps its own workdir |

## Security and Data Policy

Per `AGENTS.md`: tests and documentation use `example.com` only. Cache and run
artifacts may contain real target data from local engagements — they live under
`data/recon-cache/` and `runs/` (already gitignored or local-only). Do not
commit cache contents or use real targets in unit test fixtures.

## Testing

| Test | Asserts |
|------|---------|
| `TestSanitizeTargetCacheKey` | URL variants map to same slug |
| `TestPublishImportRoundTrip` | Bundle written and imported into temp workdir |
| `TestFindBundleInvalid` | Empty `{}` recon rejected |
| `TestResolvePolicyNonTTY` | Defaults to reuse when bundle exists |
| `TestResolvePolicyFlagNew` | `--recon new` skips lookup |
| `TestRunReconSkipsBootstrapWhenCached` | Mock executor not called on reuse |
| Integration | Temp cache + fake bundle → run completes without iter01 tool logs |

All fixtures use `example.com` and temp directories.

## Out of Scope (YAGNI)

- Per-tool partial refresh (re-run only nuclei).
- Remote/shared cache (S3, team server).
- Automatic TTL expiry without user choice.
- Separate `neurosploit recon` subcommand.
- Re-synthesizing recon JSON from tool logs via LLM on reuse (cached JSON is
  sufficient).

## Parity Note

Rust upstream writes recon artifacts for downstream reuse but has no cache layer.
This is a **Go enhancement**; document in `docs/PARITY.md` after implementation.

## Success Criteria

1. Second run against the same target (non-TTY) completes recon phase in <1s
   without bootstrap tool execution.
2. Interactive run shows reuse prompt when cache exists.
3. `--recon new` always runs full bootstrap stack.
4. Cache bundle is human-inspectable under `data/recon-cache/<slug>/`.
5. All existing tests pass; new reconcache tests cover publish/import/policy.
