# Strict Tool Loop and Prompt Cache Design

## Goal

Make NeuroSploit's agent loop resilient when models call tools with malformed
arguments. Tool calls should be validated before execution, safe mistakes should
be normalized, invalid calls should produce actionable repair observations, and
the prompt shape should keep stable instructions cache-friendly across loop
iterations.

The design covers all model paths, phased so the API/native tool loop receives
the strict gateway first and subscription CLI/bootstrap execution reuses the same
validator next.

## Current Problem

The current `internal/toolloop` can retry after an error, but it sends bad calls
to the executor before the model gets feedback. Tool recipes describe argument
placement and basic JSON types, but they do not express semantic constraints
such as "nmap target must be a host or IP" or "katana depth must be an integer in
a bounded range." Bootstrap tools also derive default arguments by parameter
name, so a full URL can be passed to a host-only tool.

Prompt history is appended as plain text. Static doctrine, tool descriptions,
and growing observations are resent together every iteration, which weakens
provider-side caching and gives models less structured repair context than
native assistant/tool-message transcripts.

Concrete failures this design addresses:

- `nmap` called with `http://example.com/path` instead of `example.com`.
- `katana` called with `depth: "d3"` or `additional_args: "-d3"` instead of a
  typed depth value.
- A tool error ends the useful path because the next model step receives only a
  generic command failure instead of a precise parameter contract violation.

## Approach

Use a strict typed tool gateway as the core fix, with a later path toward a full
planner/executor split. Prompt-only rules are not sufficient because model
instruction-following is probabilistic. A full plan validator is valuable, but
it is larger than required to eliminate malformed calls today.

The recommended implementation is:

1. Add semantic parameter contracts to tool recipes.
2. Validate and normalize every tool call before execution.
3. Feed validation results back to the model as structured observations.
4. Refactor prompt/transcript construction so stable instructions and dynamic
   state are separated.
5. Reuse the same validator in API tool loops, subscription CLI bootstrap
   tools, and default tool argument derivation.

## Tool Contracts

Extend `tools.Parameter` with semantic fields:

```yaml
target_format: host | url | domain | ip | cidr | host_or_ip | url_with_fuzz
min: 1
max: 10
enum: ["GET", "POST"]
pattern: "^[A-Za-z0-9._:-]+$"
allow_shell: false
```

These fields complement the existing `type`, `required`, `flag`, `format`,
`position`, and `default` metadata. They should also be reflected in generated
function schemas where the OpenAI-compatible schema supports them.

Initial recipe annotations should cover common high-impact tools:

| Tool | Parameter contract |
|---|---|
| `nmap`, `rustscan`, `naabu` | target is `host_or_ip`; ports are a numeric list/range pattern |
| `katana`, `httpx`, `whatweb`, `nuclei`, `curl`, `wget` | target/url is `url` |
| `ffuf` | url is `url_with_fuzz`; wordlist path is required |
| `sqlmap` | url is `url`; method enum if supplied |
| `subfinder`, `amass`, `dig`, `whois` | domain is `domain` |

`additional_args` should become opt-in and validated. Recipes that keep it must
declare it safe for that tool and reject shell metacharacters or disallowed
flags. Prefer first-class typed parameters over broad `additional_args`.

## Validator and Normalizer

Add a validation API in `internal/tools`, for example:

```go
type ValidationIssue struct {
    Parameter string
    Code      string
    Expected  string
    Received  string
    Examples  []string
}

type ValidationWarning struct {
    Parameter string
    Message   string
    Original  any
    Normalized any
}

type ValidationResult struct {
    Args     map[string]any
    Issues   []ValidationIssue
    Warnings []ValidationWarning
    Runnable bool
}

func ValidateCall(tool Tool, args map[string]any, engagementTarget string) ValidationResult
```

Safe normalization examples:

- Convert `https://example.com/a?b=c` to `example.com` for `host_or_ip`.
- Add a scheme for URL-only web tools when the engagement target already has a
  known scheme or when `https://` is the configured default.
- Convert JSON numbers represented as strings when the value is unambiguous,
  such as `"3"` to `3`.

Hard validation failures:

- `depth: "d3"` for an integer parameter.
- Full URL for a `domain` parameter when the host is ambiguous or outside scope.
- Shell metacharacters in untrusted string parameters.
- Unsupported flags in `additional_args`.
- Required `FUZZ` marker missing from `url_with_fuzz`.

The validator must not expand scan scope. Normalization can strip a URL to its
host for host-only tools, but it must not convert a different host, follow
redirect-derived scope, or infer additional targets.

## Repair-Aware Tool Loop

Update `internal/toolloop.Loop` so every call follows this path:

1. Parse model tool calls.
2. Lookup the tool recipe.
3. Validate and normalize call arguments.
4. If valid, execute the normalized command.
5. If normalized, append an observation showing original args, normalized args,
   and the command that actually ran.
6. If invalid, do not execute. Append a `VALIDATION_ERROR` observation with the
   exact parameter issue and valid examples.
7. Let the model continue from the validation observation.
8. Stop repeated identical invalid calls after a small per-call budget.

Add a separate repair budget, such as `MaxRepairAttempts`, so malformed calls do
not consume the whole engagement loop. The default can be 2 or 3 repeated
invalid attempts per tool/argument fingerprint.

Validation observations should be concise and machine-readable:

```text
OBSERVATION [tool=katana status=VALIDATION_ERROR id=call_2]:
parameter: depth
expected: integer between 1 and 10
received: "d3"
examples:
- {"target":"https://example.com","depth":3}
```

This gives the LLM a chance to repair the call without allowing bad commands to
run.

## Prompt Cache and Transcript Shape

Split prompt construction into stable and dynamic sections.

Stable prefix:

- ReAct/tool doctrine.
- Tool contract summaries and generated function schemas.
- Static examples for common target shapes.
- Agent methodology and injected skill blocks.

Dynamic suffix:

- Engagement target and operator focus.
- Recon state and phase objective.
- Latest observations, validation errors, and tool summaries.
- Compact run memory for prior useful observations.

For API models, introduce a message abstraction that can represent:

- `system`: stable doctrine and tool contracts.
- `user`: task, target, and current objective.
- `assistant`: tool calls.
- `tool`: tool result or validation error.
- `user`: continuation instruction.

Keep current string-based calls as wrappers for compatibility. `ChatWithTools`
can be backed by a message-based API while existing `Complete` callers continue
to pass `system` and `user` strings.

For subscription CLI models, render the same sections into a prompt file:

1. Stable doctrine and tool contracts.
2. Current task.
3. Compact dynamic state.
4. Latest observations.

Store full raw outputs on disk and feed only bounded summaries plus log paths
unless the output is small. The current "hash some info from last step" behavior
should be replaced with "summarize useful facts, preserve log references, and
include the last relevant observations."

## Integration Points

`internal/tools`

- Add semantic parameter fields.
- Add validation and normalization.
- Enrich generated schemas with enums, numeric bounds, and patterns.
- Harden `additional_args`.
- Add unit tests for recipe validation and normalization.

`toolsdata`

- Annotate target formats and bounds for common tools.
- Remove broad `additional_args` where typed parameters are enough.
- Add recipe authoring guidance.

`internal/toolloop`

- Validate before execution.
- Add repair observations.
- Add repeated-invalid-call guard.
- Preserve structured transcript data alongside the current text history.

`internal/pipeline/bootstrap_tools.go`

- Use the validator when deriving default tool args.
- Ensure host tools receive hosts and web tools receive URLs.

`internal/models` and `internal/pool`

- Introduce message-based calls for API providers.
- Keep string wrappers for existing callers.
- Preserve CLI prompt-file fallback.

`internal/pipeline/prompt.go`

- Reduce reliance on prompt-only rules.
- Keep concise examples that match schema-backed validation.

Docs

- Add a tool recipe authoring note describing semantic parameter contracts and
  examples for host-only, URL-only, and FUZZ URL tools.

## Testing

Required tests:

- `tools.ValidateCall` accepts valid calls and rejects invalid calls with precise
  issues.
- `nmap` receives `example.com` when the engagement target is
  `https://example.com/path`.
- `katana` accepts URL targets and integer depth, rejects `d3`, and reports a
  repairable validation error.
- `ffuf` rejects URLs without the `FUZZ` marker.
- `additional_args` rejects shell metacharacters and unsupported flags.
- `toolloop` test where the first call is invalid, the second call repairs it,
  and only the repaired command executes.
- `toolloop` repeated-invalid-call test stops after the configured repair
  budget.
- `bootstrap_tools` test proving host tools receive host-only targets and web
  tools receive full URLs.
- Prompt/transcript test proving stable prompt sections do not grow every
  iteration.

Before committing implementation work, run:

```bash
cd neurosploit-go
go vet ./...
go test ./... -timeout 30s
```

This matches the Go harness CI gate for vet and tests.

## Rollout

Phase 1: Add semantic fields, validator, recipe annotations, and tests.

Phase 2: Wire validation into API/native `toolloop` and add repair
observations.

Phase 3: Wire validation into subscription CLI bootstrap tools and default args.

Phase 4: Add message-based API transcript support while preserving string
compatibility.

Phase 5: Improve compact run memory and prompt rendering for cache-friendly
stable prefixes.

## Non-Goals

- Do not modify `neurosploit-rs/`.
- Do not add destructive or broader-scope tool behavior.
- Do not require provider-specific prompt cache APIs in the first pass.
- Do not replace the whole pipeline with a full planner/executor architecture in
  this design. The strict gateway should make that future change easier.

## Open Decisions

The default normalization policy is:

- Normalize obvious target-shape mistakes when scope is preserved.
- Record every normalization as a warning observation.
- Reject ambiguous or scope-expanding corrections.

The default repair policy is:

- Allow up to 2 or 3 repeated invalid attempts per tool/argument fingerprint.
- After the budget is exhausted, the loop should ask the model to choose a
  different method or provide a final answer based on available evidence.
