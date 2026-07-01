# Strict Tool Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add strict tool parameter contracts, validation/normalization, repair-aware tool-loop observations, and cache-friendlier prompt/transcript structure.

**Architecture:** Tool recipes become the source of truth for semantic argument contracts. `internal/tools` validates and normalizes calls before command construction; `internal/toolloop` turns validation failures into model-repair observations instead of running bad commands. Existing string-based model calls remain compatible while a message transcript type is introduced for structured future use.

**Tech Stack:** Go 1.26, stdlib, existing `gopkg.in/yaml.v3`, existing cobra/model pool/toolloop packages.

---

## File Structure

- Modify `neurosploit-go/internal/tools/tools.go`: extend `Parameter`, enrich schemas, call validation from `DefaultExecutor`.
- Create `neurosploit-go/internal/tools/validate.go`: semantic validation, normalization, issue/warning types, safe `additional_args` checks.
- Create `neurosploit-go/internal/tools/validate_test.go`: focused validator and schema tests.
- Modify `toolsdata/**/*.yaml`: add target formats, numeric bounds, patterns, and safe extra-arg policy to high-impact tools.
- Modify `neurosploit-go/internal/toolloop/toolloop.go`: validate before execution, emit repair observations, track repeated invalid calls, preserve structured message transcript.
- Modify `neurosploit-go/internal/toolloop/toolloop_test.go`: repair-loop tests.
- Modify `neurosploit-go/internal/pipeline/bootstrap_tools.go`: derive default args through semantic target formats and validator.
- Modify `neurosploit-go/internal/pipeline/bootstrap_tools_test.go`: prove host tools receive hosts and web tools receive URLs.
- Modify `neurosploit-go/internal/models/models.go`: add message structs and `ChatMessagesWithTools` compatibility path.
- Modify `neurosploit-go/internal/pool/pool.go`: add message-based pool method and keep current wrappers.
- Modify `neurosploit-go/internal/pipeline/prompt.go`: keep concise schema-backed tool examples.
- Create `docs/TOOL_RECIPES.md`: document semantic parameter contracts for future recipes.

---

### Task 1: Semantic Tool Contracts

**Files:**
- Modify: `neurosploit-go/internal/tools/tools.go`
- Test: `neurosploit-go/internal/tools/tools_recipes_test.go`

- [ ] **Step 1: Write the failing schema-contract test**

Add these assertions to `validateToolParameters` in `neurosploit-go/internal/tools/tools_recipes_test.go` after the existing `switch p.Format` block:

```go
		switch p.TargetFormat {
		case "", "host", "url", "domain", "ip", "cidr", "host_or_ip", "url_with_fuzz":
		default:
			t.Fatalf("parameter %q: unknown target_format %q", p.Name, p.TargetFormat)
		}
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			t.Fatalf("parameter %q: min %v > max %v", p.Name, *p.Min, *p.Max)
		}
		if p.AllowShell && p.Name != "additional_args" {
			t.Fatalf("parameter %q: allow_shell is only supported for additional_args", p.Name)
		}
```

Add this helper near `validateToolParameters`:

```go
func schemaProperty(t *testing.T, tool Tool, name string) map[string]any {
	t.Helper()
	schema := tool.FunctionDefinition()
	fn := schema["function"].(map[string]any)
	params := fn["parameters"].(map[string]any)
	props := params["properties"].(map[string]any)
	prop, ok := props[name].(map[string]any)
	if !ok {
		t.Fatalf("schema property %q missing for tool %s", name, tool.Name)
	}
	return prop
}
```

Add this test near the end of the file:

```go
func TestFunctionDefinitionIncludesSemanticConstraints(t *testing.T) {
	tool := Tool{
		Name:             "katana",
		Command:          "katana",
		ShortDescription: "crawler",
		Parameters: []Parameter{
			{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
			{Name: "depth", Type: "int", Required: false, Min: intPtr(1), Max: intPtr(10)},
			{Name: "method", Type: "string", Required: false, Enum: []string{"GET", "POST"}},
			{Name: "ports", Type: "string", Required: false, Pattern: `^\d+(,\d+)*$`},
		},
	}
	target := schemaProperty(t, tool, "target")
	if !strings.Contains(fmt.Sprint(target["description"]), "Expected format: url") {
		t.Fatalf("target description missing semantic format: %#v", target)
	}
	depth := schemaProperty(t, tool, "depth")
	if depth["minimum"] != 1 || depth["maximum"] != 10 {
		t.Fatalf("depth min/max missing: %#v", depth)
	}
	method := schemaProperty(t, tool, "method")
	if fmt.Sprint(method["enum"]) != "[GET POST]" {
		t.Fatalf("method enum missing: %#v", method)
	}
	ports := schemaProperty(t, tool, "ports")
	if ports["pattern"] != `^\d+(,\d+)*$` {
		t.Fatalf("ports pattern missing: %#v", ports)
	}
}

func intPtr(v int) *int { return &v }
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -run TestFunctionDefinitionIncludesSemanticConstraints -count=1
```

Expected: compile failure because `Parameter.TargetFormat`, `Min`, `Max`, `Enum`, `Pattern`, and `AllowShell` are not defined.

- [ ] **Step 3: Add semantic fields to `Parameter`**

In `neurosploit-go/internal/tools/tools.go`, replace the `Parameter` struct with:

```go
type Parameter struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	Description  string   `yaml:"description"`
	Required     bool     `yaml:"required,omitempty"`
	Default      any      `yaml:"default,omitempty"`
	Flag         string   `yaml:"flag,omitempty"`
	Format       string   `yaml:"format,omitempty"`
	Position     int      `yaml:"position,omitempty"`
	TargetFormat string   `yaml:"target_format,omitempty"`
	Min          *int     `yaml:"min,omitempty"`
	Max          *int     `yaml:"max,omitempty"`
	Enum         []string `yaml:"enum,omitempty"`
	Pattern      string   `yaml:"pattern,omitempty"`
	AllowShell   bool     `yaml:"allow_shell,omitempty"`
	AllowedFlags []string `yaml:"allowed_flags,omitempty"`
}
```

In `FunctionDefinition`, replace the schema construction block:

```go
		schema := map[string]any{
			"type":        jsonType(p.Type),
			"description": p.Description,
		}
```

with:

```go
		desc := p.Description
		if p.TargetFormat != "" {
			desc = strings.TrimSpace(desc)
			if desc != "" {
				desc += " "
			}
			desc += fmt.Sprintf("Expected format: %s.", p.TargetFormat)
		}
		schema := map[string]any{
			"type":        jsonType(p.Type),
			"description": desc,
		}
		if p.Min != nil {
			schema["minimum"] = *p.Min
		}
		if p.Max != nil {
			schema["maximum"] = *p.Max
		}
		if len(p.Enum) > 0 {
			values := make([]any, 0, len(p.Enum))
			for _, v := range p.Enum {
				values = append(values, v)
			}
			schema["enum"] = values
		}
		if p.Pattern != "" {
			schema["pattern"] = p.Pattern
		}
```

- [ ] **Step 4: Run the semantic schema test**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -run TestFunctionDefinitionIncludesSemanticConstraints -count=1
```

Expected: pass.

- [ ] **Step 5: Run all tool tests**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add neurosploit-go/internal/tools/tools.go neurosploit-go/internal/tools/tools_recipes_test.go
git commit -m "feat: add semantic tool parameter contracts"
```

---

### Task 2: Tool Call Validator and Normalizer

**Files:**
- Create: `neurosploit-go/internal/tools/validate.go`
- Create: `neurosploit-go/internal/tools/validate_test.go`
- Modify: `neurosploit-go/internal/tools/tools.go`

- [ ] **Step 1: Write failing validator tests**

Create `neurosploit-go/internal/tools/validate_test.go`:

```go
package tools

import (
	"strings"
	"testing"
)

func TestValidateCallNormalizesHostOnlyTarget(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com/app?q=1"}, "https://example.com")
	if !res.Runnable {
		t.Fatalf("expected runnable, got issues: %+v", res.Issues)
	}
	if got := res.Args["target"]; got != "example.com" {
		t.Fatalf("target = %v want example.com", got)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Message, "converted URL to host") {
		t.Fatalf("expected normalization warning, got %+v", res.Warnings)
	}
}

func TestValidateCallRejectsOutOfScopeNormalization(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://other.example"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected not runnable: %+v", res)
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != "scope_mismatch" {
		t.Fatalf("unexpected issues: %+v", res.Issues)
	}
}

func TestValidateCallRejectsBadInteger(t *testing.T) {
	tool := Tool{Name: "katana", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
		{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com", "depth": "d3"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected validation failure")
	}
	if len(res.Issues) != 1 || res.Issues[0].Parameter != "depth" || res.Issues[0].Code != "invalid_integer" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}

func TestValidateCallConvertsNumericString(t *testing.T) {
	tool := Tool{Name: "katana", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
		{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com", "depth": "3"}, "https://example.com")
	if !res.Runnable {
		t.Fatalf("expected runnable, got %+v", res.Issues)
	}
	if got := res.Args["depth"]; got != 3 {
		t.Fatalf("depth = %#v want 3", got)
	}
}

func TestValidateCallRejectsMissingFuzzMarker(t *testing.T) {
	tool := Tool{Name: "ffuf", Parameters: []Parameter{
		{Name: "url", Type: "string", Required: true, TargetFormat: "url_with_fuzz"},
	}}
	res := ValidateCall(tool, map[string]any{"url": "https://example.com/path"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected missing FUZZ marker failure")
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != "missing_fuzz_marker" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}

func TestValidateCallRejectsUnsafeAdditionalArgs(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
		{Name: "additional_args", Type: "string", AllowShell: false, AllowedFlags: []string{"-T4"}},
	}}
	res := ValidateCall(tool, map[string]any{"target": "example.com", "additional_args": "-T4; rm -rf /"}, "example.com")
	if res.Runnable {
		t.Fatalf("expected unsafe additional_args failure")
	}
	if len(res.Issues) == 0 || res.Issues[0].Code != "unsafe_additional_args" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}
```

- [ ] **Step 2: Run validator tests to verify they fail**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -run 'TestValidateCall' -count=1
```

Expected: compile failure because `ValidateCall` and its result types are missing.

- [ ] **Step 3: Implement validator types and entrypoint**

Create `neurosploit-go/internal/tools/validate.go`:

```go
package tools

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type ValidationIssue struct {
	Parameter string
	Code      string
	Expected  string
	Received  string
	Examples  []string
}

type ValidationWarning struct {
	Parameter  string
	Message    string
	Original   any
	Normalized any
}

type ValidationResult struct {
	Args     map[string]any
	Issues   []ValidationIssue
	Warnings []ValidationWarning
	Runnable bool
}

func ValidateCall(tool Tool, args map[string]any, engagementTarget string) ValidationResult {
	normalized := copyArgs(args)
	var issues []ValidationIssue
	var warnings []ValidationWarning
	for _, p := range tool.Parameters {
		v, provided := normalized[p.Name]
		if !provided && p.Default != nil {
			v = p.Default
			normalized[p.Name] = v
			provided = true
		}
		if p.Required && !provided {
			issues = append(issues, issue(p, "missing_required", "required parameter", "", examplesFor(p)))
			continue
		}
		if !provided {
			continue
		}
		nv, w, paramIssues := validateParameter(p, v, engagementTarget)
		if len(w) > 0 {
			warnings = append(warnings, w...)
		}
		if len(paramIssues) > 0 {
			issues = append(issues, paramIssues...)
			continue
		}
		normalized[p.Name] = nv
	}
	return ValidationResult{
		Args:     normalized,
		Issues:   issues,
		Warnings: warnings,
		Runnable: len(issues) == 0,
	}
}

func copyArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}
	return out
}

func validateParameter(p Parameter, v any, engagementTarget string) (any, []ValidationWarning, []ValidationIssue) {
	var warnings []ValidationWarning
	var issues []ValidationIssue
	nv := v
	switch strings.ToLower(p.Type) {
	case "int", "integer":
		converted, ok := asInt(v)
		if !ok {
			return v, nil, []ValidationIssue{issue(p, "invalid_integer", integerExpected(p), fmt.Sprint(v), examplesFor(p))}
		}
		nv = converted
		if p.Min != nil && converted < *p.Min {
			issues = append(issues, issue(p, "below_minimum", integerExpected(p), fmt.Sprint(v), examplesFor(p)))
		}
		if p.Max != nil && converted > *p.Max {
			issues = append(issues, issue(p, "above_maximum", integerExpected(p), fmt.Sprint(v), examplesFor(p)))
		}
	case "bool", "boolean":
		if _, ok := v.(bool); !ok {
			return v, nil, []ValidationIssue{issue(p, "invalid_boolean", "boolean", fmt.Sprint(v), examplesFor(p))}
		}
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" && p.Required {
			issues = append(issues, issue(p, "empty_value", "non-empty string", fmt.Sprint(v), examplesFor(p)))
		}
		nv = s
	}
	if len(issues) > 0 {
		return nv, warnings, issues
	}
	if len(p.Enum) > 0 {
		s := fmt.Sprint(nv)
		if !stringIn(s, p.Enum) {
			return nv, warnings, []ValidationIssue{issue(p, "invalid_enum", "one of: "+strings.Join(p.Enum, ", "), s, examplesFor(p))}
		}
	}
	if p.Pattern != "" {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nv, warnings, []ValidationIssue{issue(p, "invalid_pattern", "valid regex pattern in recipe", p.Pattern, nil)}
		}
		if !re.MatchString(fmt.Sprint(nv)) {
			return nv, warnings, []ValidationIssue{issue(p, "pattern_mismatch", p.Pattern, fmt.Sprint(nv), examplesFor(p))}
		}
	}
	if p.Name == "additional_args" {
		if extraIssues := validateAdditionalArgs(p, fmt.Sprint(nv)); len(extraIssues) > 0 {
			return nv, warnings, extraIssues
		}
	}
	if p.TargetFormat != "" {
		target, targetWarnings, targetIssues := normalizeTarget(p, fmt.Sprint(nv), engagementTarget)
		if len(targetWarnings) > 0 {
			warnings = append(warnings, targetWarnings...)
		}
		if len(targetIssues) > 0 {
			return nv, warnings, targetIssues
		}
		nv = target
	}
	return nv, warnings, nil
}

func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		if x == float64(int(x)) {
			return int(x), true
		}
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(x))
		return i, err == nil
	}
	return 0, false
}

func integerExpected(p Parameter) string {
	if p.Min != nil && p.Max != nil {
		return fmt.Sprintf("integer between %d and %d", *p.Min, *p.Max)
	}
	if p.Min != nil {
		return fmt.Sprintf("integer >= %d", *p.Min)
	}
	if p.Max != nil {
		return fmt.Sprintf("integer <= %d", *p.Max)
	}
	return "integer"
}

func normalizeTarget(p Parameter, value, engagementTarget string) (string, []ValidationWarning, []ValidationIssue) {
	switch p.TargetFormat {
	case "url", "url_with_fuzz":
		u, err := parseURLWithDefaultScheme(value, engagementTarget)
		if err != nil {
			return value, nil, []ValidationIssue{issue(p, "invalid_url", "absolute URL", value, examplesFor(p))}
		}
		if !sameScope(u.Hostname(), engagementTarget) {
			return value, nil, []ValidationIssue{issue(p, "scope_mismatch", "target within engagement scope", value, examplesFor(p))}
		}
		if p.TargetFormat == "url_with_fuzz" && !strings.Contains(value, "FUZZ") {
			return value, nil, []ValidationIssue{issue(p, "missing_fuzz_marker", "URL containing FUZZ", value, examplesFor(p))}
		}
		normalized := u.String()
		if strings.Contains(value, "FUZZ") && !strings.Contains(normalized, "FUZZ") {
			normalized = value
		}
		return normalized, warningIfChanged(p, value, normalized, "normalized URL"), nil
	case "host", "host_or_ip", "domain", "ip":
		host := value
		if strings.Contains(value, "://") {
			u, err := url.Parse(value)
			if err != nil || u.Hostname() == "" {
				return value, nil, []ValidationIssue{issue(p, "invalid_host", "hostname or IP", value, examplesFor(p))}
			}
			host = u.Hostname()
			if !sameScope(host, engagementTarget) {
				return value, nil, []ValidationIssue{issue(p, "scope_mismatch", "target within engagement scope", value, examplesFor(p))}
			}
		}
		host = strings.TrimSpace(host)
		if host == "" || strings.ContainsAny(host, "/?#") {
			return value, nil, []ValidationIssue{issue(p, "invalid_host", "hostname or IP", value, examplesFor(p))}
		}
		if p.TargetFormat == "ip" && net.ParseIP(host) == nil {
			return value, nil, []ValidationIssue{issue(p, "invalid_ip", "IP address", value, examplesFor(p))}
		}
		if p.TargetFormat == "domain" && net.ParseIP(host) != nil {
			return value, nil, []ValidationIssue{issue(p, "invalid_domain", "domain name", value, examplesFor(p))}
		}
		return host, warningIfChanged(p, value, host, "converted URL to host"), nil
	case "cidr":
		if _, _, err := net.ParseCIDR(value); err != nil {
			return value, nil, []ValidationIssue{issue(p, "invalid_cidr", "CIDR range", value, examplesFor(p))}
		}
		return value, nil, nil
	default:
		return value, nil, nil
	}
}

func parseURLWithDefaultScheme(value, engagementTarget string) (*url.URL, error) {
	raw := strings.TrimSpace(value)
	if !strings.Contains(raw, "://") {
		scheme := "https"
		if eu, err := url.Parse(engagementTarget); err == nil && eu.Scheme != "" {
			scheme = eu.Scheme
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid url")
	}
	return u, nil
}

func sameScope(host, engagementTarget string) bool {
	if engagementTarget == "" {
		return true
	}
	base := engagementTarget
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return true
	}
	return strings.EqualFold(host, u.Hostname())
}

func validateAdditionalArgs(p Parameter, value string) []ValidationIssue {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if !p.AllowShell && strings.ContainsAny(value, "|;&`$<>") {
		return []ValidationIssue{issue(p, "unsafe_additional_args", "safe allowlisted flags only", value, nil)}
	}
	if len(p.AllowedFlags) == 0 {
		return []ValidationIssue{issue(p, "unsupported_additional_args", "recipe-defined allowed_flags", value, nil)}
	}
	fields := strings.Fields(value)
	for _, f := range fields {
		if strings.HasPrefix(f, "-") && !stringIn(f, p.AllowedFlags) {
			return []ValidationIssue{issue(p, "unsupported_flag", "one of: "+strings.Join(p.AllowedFlags, ", "), f, nil)}
		}
	}
	return nil
}

func issue(p Parameter, code, expected, received string, examples []string) ValidationIssue {
	return ValidationIssue{Parameter: p.Name, Code: code, Expected: expected, Received: received, Examples: examples}
}

func warningIfChanged(p Parameter, original, normalized, msg string) []ValidationWarning {
	if original == normalized {
		return nil
	}
	return []ValidationWarning{{Parameter: p.Name, Message: msg, Original: original, Normalized: normalized}}
}

func examplesFor(p Parameter) []string {
	switch p.TargetFormat {
	case "host", "host_or_ip":
		return []string{`{"target":"example.com"}`, `{"target":"192.0.2.10"}`}
	case "url":
		return []string{`{"target":"https://example.com"}`, `{"url":"https://example.com/path"}`}
	case "url_with_fuzz":
		return []string{`{"url":"https://example.com/FUZZ"}`}
	case "domain":
		return []string{`{"domain":"example.com"}`}
	}
	if strings.Contains(strings.ToLower(p.Type), "int") {
		return []string{fmt.Sprintf(`{"%s":3}`, p.Name)}
	}
	return nil
}

func stringIn(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Call validator from the executor**

In `DefaultExecutor.Execute` in `neurosploit-go/internal/tools/tools.go`, replace:

```go
	args, err := BuildCommand(tool, call.Args)
```

with:

```go
	validation := ValidateCall(tool, call.Args, "")
	if !validation.Runnable {
		res.IsError = true
		res.Error = FormatValidationIssues(validation.Issues)
		return res, nil
	}
	args, err := BuildCommand(tool, validation.Args)
```

Add this function to `validate.go`:

```go
func FormatValidationIssues(issues []ValidationIssue) string {
	if len(issues) == 0 {
		return ""
	}
	var b strings.Builder
	for i, issue := range issues {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %s (expected %s, received %s)", issue.Parameter, issue.Code, issue.Expected, issue.Received)
	}
	return b.String()
}
```

- [ ] **Step 5: Run validator tests**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -run 'TestValidateCall' -count=1
```

Expected: pass.

- [ ] **Step 6: Run all tool tests**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -count=1
```

Expected: pass.

- [ ] **Step 7: Commit**

Run:

```bash
git add neurosploit-go/internal/tools/validate.go neurosploit-go/internal/tools/validate_test.go neurosploit-go/internal/tools/tools.go
git commit -m "feat: validate tool call parameters"
```

---

### Task 3: Annotate Core Tool Recipes

**Files:**
- Modify: `toolsdata/network/nmap.yaml`
- Modify: `toolsdata/network/rustscan.yaml`
- Modify: `toolsdata/network/naabu.yaml`
- Modify: `toolsdata/web/katana.yaml`
- Modify: `toolsdata/web/httpx.yaml`
- Modify: `toolsdata/web/whatweb.yaml`
- Modify: `toolsdata/web/nuclei.yaml`
- Modify: `toolsdata/web/curl.yaml`
- Modify: `toolsdata/web/wget.yaml`
- Modify: `toolsdata/web/ffuf.yaml`
- Modify: `toolsdata/web/sqlmap.yaml`
- Modify: `toolsdata/network/subfinder.yaml`
- Modify: `toolsdata/network/amass.yaml`
- Modify: `toolsdata/network/dig.yaml`
- Modify: `toolsdata/network/whois.yaml`
- Test: `neurosploit-go/internal/tools/tools_recipes_test.go`

- [ ] **Step 1: Write failing recipe-specific validation tests**

Add to `neurosploit-go/internal/tools/tools_recipes_test.go`:

```go
func TestCoreRecipesDeclareTargetFormats(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	reg, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"nmap":      {"target": "host_or_ip"},
		"rustscan":  {"target": "host_or_ip"},
		"naabu":     {"target": "host_or_ip"},
		"katana":    {"target": "url"},
		"httpx":     {"target": "url"},
		"whatweb":   {"target": "url"},
		"nuclei":    {"target": "url"},
		"curl":      {"url": "url"},
		"wget":      {"url": "url"},
		"ffuf":      {"url": "url_with_fuzz"},
		"sqlmap":    {"url": "url"},
		"subfinder": {"domain": "domain"},
		"amass":     {"domain": "domain"},
		"dig":       {"domain": "domain"},
		"whois":     {"domain": "domain"},
	}
	for toolName, params := range want {
		tool, ok := reg.Get(toolName)
		if !ok {
			t.Fatalf("tool %s missing", toolName)
		}
		for paramName, format := range params {
			p, ok := findParam(tool, paramName)
			if !ok {
				t.Fatalf("%s.%s missing", toolName, paramName)
			}
			if p.TargetFormat != format {
				t.Fatalf("%s.%s target_format = %q want %q", toolName, paramName, p.TargetFormat, format)
			}
		}
	}
}

func findParam(tool Tool, name string) (Parameter, bool) {
	for _, p := range tool.Parameters {
		if p.Name == name {
			return p, true
		}
	}
	return Parameter{}, false
}
```

- [ ] **Step 2: Run the target-format test to verify it fails**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -run TestCoreRecipesDeclareTargetFormats -count=1
```

Expected: fail because recipes do not declare `target_format`.

- [ ] **Step 3: Annotate host tools**

In `toolsdata/network/nmap.yaml`, under `target`, add:

```yaml
    target_format: host_or_ip
```

Under `ports`, add:

```yaml
    pattern: '^([0-9]{1,5})(-[0-9]{1,5})?(,([0-9]{1,5})(-[0-9]{1,5})?)*$'
```

Under `additional_args`, add:

```yaml
    allowed_flags: [-T4, -T3, -A, -O, --version-light]
```

Apply `target_format: host_or_ip` to the primary target parameter in `toolsdata/network/rustscan.yaml` and `toolsdata/network/naabu.yaml`. Add port patterns to their port parameters if present.

- [ ] **Step 4: Annotate URL tools**

Add `target_format: url` to the URL-like primary parameter in:

```text
toolsdata/web/katana.yaml
toolsdata/web/httpx.yaml
toolsdata/web/whatweb.yaml
toolsdata/web/nuclei.yaml
toolsdata/web/curl.yaml
toolsdata/web/wget.yaml
toolsdata/web/sqlmap.yaml
```

For `toolsdata/web/katana.yaml`, add depth bounds:

```yaml
    min: 1
    max: 10
```

For `toolsdata/web/curl.yaml`, add method enum to the method parameter if present:

```yaml
    enum: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
```

For `toolsdata/web/ffuf.yaml`, set:

```yaml
    target_format: url_with_fuzz
```

on the `url` parameter.

- [ ] **Step 5: Annotate domain tools**

Add `target_format: domain` to the domain parameter in:

```text
toolsdata/network/subfinder.yaml
toolsdata/network/amass.yaml
toolsdata/network/dig.yaml
toolsdata/network/whois.yaml
```

- [ ] **Step 6: Run recipe tests**

Run:

```bash
cd neurosploit-go
go test ./internal/tools -count=1
```

Expected: pass.

- [ ] **Step 7: Commit**

Run:

```bash
git add toolsdata neurosploit-go/internal/tools/tools_recipes_test.go
git commit -m "feat: annotate tool recipe parameter contracts"
```

---

### Task 4: Repair-Aware Tool Loop

**Files:**
- Modify: `neurosploit-go/internal/toolloop/toolloop.go`
- Modify: `neurosploit-go/internal/toolloop/toolloop_test.go`

- [ ] **Step 1: Write failing repair-loop tests**

Add to `neurosploit-go/internal/toolloop/toolloop_test.go`:

```go
type recordingExecutor struct {
	calls []tools.ToolCall
}

func (r *recordingExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	r.calls = append(r.calls, call)
	return tools.ToolResult{Name: call.Name, ID: call.ID, Output: "ok", ExitCode: 0}, nil
}

func TestLoopValidationErrorAllowsRepair(t *testing.T) {
	caller := &mockCaller{responses: []string{
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":3}}</tool_call>`,
		`done`,
	}}
	exec := &recordingExecutor{}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 4, MaxRepairAttempts: 2}
	final, obs, err := loop.Run(context.Background(), "Test.", "Crawl", []tools.Tool{
		{Name: "katana", Command: "katana", ShortDescription: "Crawler", Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
			{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
		}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "done" {
		t.Fatalf("final = %q", final)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("expected one executed call, got %d", len(exec.calls))
	}
	if exec.calls[0].Args["depth"] != 3 {
		t.Fatalf("executed depth = %#v", exec.calls[0].Args["depth"])
	}
	if len(obs) != 2 {
		t.Fatalf("expected validation observation and execution observation, got %d", len(obs))
	}
	if !obs[0].Result.IsError || !strings.Contains(obs[0].Result.Error, "VALIDATION_ERROR") {
		t.Fatalf("first observation should be validation error: %+v", obs[0])
	}
}

func TestLoopStopsRepeatedInvalidCalls(t *testing.T) {
	caller := &mockCaller{responses: []string{
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
	}}
	exec := &recordingExecutor{}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 5, MaxRepairAttempts: 2}
	_, _, err := loop.Run(context.Background(), "Test.", "Crawl", []tools.Tool{
		{Name: "katana", Command: "katana", ShortDescription: "Crawler", Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
			{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "repeated invalid tool call") {
		t.Fatalf("expected repeated invalid error, got %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("invalid calls must not execute, got %d", len(exec.calls))
	}
}
```

Add this helper if Task 1's `intPtr` is not visible in this package:

```go
func intPtr(v int) *int { return &v }
```

- [ ] **Step 2: Run repair-loop tests to verify they fail**

Run:

```bash
cd neurosploit-go
go test ./internal/toolloop -run 'TestLoopValidation|TestLoopStops' -count=1
```

Expected: compile failure because `Loop.MaxRepairAttempts` is missing, or failing behavior because invalid calls execute.

- [ ] **Step 3: Add repair state to `Loop`**

In `neurosploit-go/internal/toolloop/toolloop.go`, extend `Loop`:

```go
type Loop struct {
	Caller            Caller
	Executor          tools.Executor
	MaxIter           int
	MaxRepairAttempts int
	Progress          chan<- string
}
```

At the top of `Run`, after `MaxIter` defaulting, add:

```go
	if l.MaxRepairAttempts == 0 {
		l.MaxRepairAttempts = 2
	}
	invalidCounts := map[string]int{}
	toolsByName := map[string]tools.Tool{}
	for _, t := range toolList {
		toolsByName[t.Name] = t
	}
```

- [ ] **Step 4: Validate before execution in the loop**

Inside the `for _, call := range calls` loop in `Run`, replace the current direct execution block with:

```go
			tool, ok := toolsByName[call.Name]
			if !ok {
				result := tools.ToolResult{Name: call.Name, ID: call.ID, IsError: true, Error: "VALIDATION_ERROR: unknown tool"}
				observations = append(observations, Observation{Call: call, Result: result})
				history += "\n\n" + formatObservation(call, result)
				continue
			}
			validation := tools.ValidateCall(tool, call.Args, "")
			if !validation.Runnable {
				key := invalidFingerprint(call, validation.Issues)
				invalidCounts[key]++
				result := tools.ToolResult{
					Name:    call.Name,
					ID:      call.ID,
					IsError: true,
					Error:   formatValidationObservation(call, validation),
				}
				l.emit(formatToolProgress(call.Name, result))
				observations = append(observations, Observation{Call: call, Result: result})
				history += "\n\n" + formatObservation(call, result)
				if invalidCounts[key] > l.MaxRepairAttempts {
					return "", observations, fmt.Errorf("repeated invalid tool call: %s", call.Name)
				}
				continue
			}
			if len(validation.Warnings) > 0 {
				history += "\n\n" + formatNormalizationObservation(call, validation)
			}
			call.Args = validation.Args
			l.emit(fmt.Sprintf("tool run: %s", call.Name))
			callCtx := tools.ContextWithIteration(ctx, i+1)
			result, err := l.Executor.Execute(callCtx, call)
			if err != nil {
				result = tools.ToolResult{IsError: true, Error: err.Error()}
			}
			l.emit(formatToolProgress(call.Name, result))
			observations = append(observations, Observation{Call: call, Result: result})
			history += "\n\n" + formatObservation(call, result)
```

- [ ] **Step 5: Add formatting helpers**

Add to `toolloop.go` near `formatObservation`:

```go
func formatValidationObservation(call tools.ToolCall, validation tools.ValidationResult) string {
	var b strings.Builder
	b.WriteString("VALIDATION_ERROR\n")
	for _, issue := range validation.Issues {
		fmt.Fprintf(&b, "parameter: %s\n", issue.Parameter)
		fmt.Fprintf(&b, "code: %s\n", issue.Code)
		fmt.Fprintf(&b, "expected: %s\n", issue.Expected)
		fmt.Fprintf(&b, "received: %s\n", issue.Received)
		if len(issue.Examples) > 0 {
			b.WriteString("examples:\n")
			for _, ex := range issue.Examples {
				fmt.Fprintf(&b, "- %s\n", ex)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func formatNormalizationObservation(call tools.ToolCall, validation tools.ValidationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OBSERVATION [tool=%s status=NORMALIZED id=%s]:\n", call.Name, call.ID)
	for _, warning := range validation.Warnings {
		fmt.Fprintf(&b, "parameter: %s\nmessage: %s\noriginal: %v\nnormalized: %v\n", warning.Parameter, warning.Message, warning.Original, warning.Normalized)
	}
	return strings.TrimSpace(b.String())
}

func invalidFingerprint(call tools.ToolCall, issues []tools.ValidationIssue) string {
	var b strings.Builder
	b.WriteString(call.Name)
	for _, issue := range issues {
		fmt.Fprintf(&b, "|%s=%s:%s", issue.Parameter, issue.Code, issue.Received)
	}
	return b.String()
}
```

- [ ] **Step 6: Run repair-loop tests**

Run:

```bash
cd neurosploit-go
go test ./internal/toolloop -run 'TestLoopValidation|TestLoopStops' -count=1
```

Expected: pass.

- [ ] **Step 7: Run all toolloop tests**

Run:

```bash
cd neurosploit-go
go test ./internal/toolloop -count=1
```

Expected: pass.

- [ ] **Step 8: Commit**

Run:

```bash
git add neurosploit-go/internal/toolloop/toolloop.go neurosploit-go/internal/toolloop/toolloop_test.go
git commit -m "feat: add repair-aware tool loop validation"
```

---

### Task 5: Bootstrap Tool Argument Validation

**Files:**
- Modify: `neurosploit-go/internal/pipeline/bootstrap_tools.go`
- Modify: `neurosploit-go/internal/pipeline/bootstrap_tools_test.go`

- [ ] **Step 1: Write failing bootstrap tests**

Add to `neurosploit-go/internal/pipeline/bootstrap_tools_test.go`:

```go
func TestDefaultToolArgsUsesTargetFormat(t *testing.T) {
	nmap := tools.Tool{Name: "nmap", Parameters: []tools.Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	args, ok := defaultToolArgs(nmap, "https://example.com/app?q=1")
	if !ok {
		t.Fatal("expected default args")
	}
	if args["target"] != "example.com" {
		t.Fatalf("nmap target = %v want example.com", args["target"])
	}

	katana := tools.Tool{Name: "katana", Parameters: []tools.Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
	}}
	args, ok = defaultToolArgs(katana, "https://example.com/app?q=1")
	if !ok {
		t.Fatal("expected default args")
	}
	if args["target"] != "https://example.com/app?q=1" {
		t.Fatalf("katana target = %v want full URL", args["target"])
	}
}

func TestDefaultToolArgsRequiresFuzzMarkerForFfuf(t *testing.T) {
	ffuf := tools.Tool{Name: "ffuf", Parameters: []tools.Parameter{
		{Name: "url", Type: "string", Required: true, TargetFormat: "url_with_fuzz"},
	}}
	if _, ok := defaultToolArgs(ffuf, "https://example.com"); ok {
		t.Fatal("ffuf should not receive default args without FUZZ")
	}
}
```

- [ ] **Step 2: Run bootstrap tests to verify they fail**

Run:

```bash
cd neurosploit-go
go test ./internal/pipeline -run TestDefaultToolArgs -count=1
```

Expected: fail because `nmap` currently receives the full URL.

- [ ] **Step 3: Update default arg derivation**

In `neurosploit-go/internal/pipeline/bootstrap_tools.go`, replace the `switch p.Name` block inside `defaultToolArgs` with:

```go
		switch {
		case p.TargetFormat == "host" || p.TargetFormat == "host_or_ip" || p.TargetFormat == "domain" || p.TargetFormat == "ip":
			args[p.Name] = host
		case p.TargetFormat == "url":
			args[p.Name] = target
		case p.TargetFormat == "url_with_fuzz":
			return nil, false
		case p.Name == "target" || p.Name == "url":
			args[p.Name] = target
		case p.Name == "host" || p.Name == "domain":
			args[p.Name] = host
		default:
			return nil, false
		}
```

Before returning `args, true`, add:

```go
	validation := tools.ValidateCall(tool, args, target)
	if !validation.Runnable {
		return nil, false
	}
	return validation.Args, true
```

and remove the old final `return args, true`.

- [ ] **Step 4: Run bootstrap tests**

Run:

```bash
cd neurosploit-go
go test ./internal/pipeline -run TestDefaultToolArgs -count=1
```

Expected: pass.

- [ ] **Step 5: Run pipeline tests**

Run:

```bash
cd neurosploit-go
go test ./internal/pipeline -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add neurosploit-go/internal/pipeline/bootstrap_tools.go neurosploit-go/internal/pipeline/bootstrap_tools_test.go
git commit -m "fix: validate bootstrap tool arguments"
```

---

### Task 6: Structured Message Transcript Compatibility

**Files:**
- Modify: `neurosploit-go/internal/models/models.go`
- Modify: `neurosploit-go/internal/models/models_test.go`
- Modify: `neurosploit-go/internal/pool/pool.go`
- Modify: `neurosploit-go/internal/pool/pool_test.go`

- [ ] **Step 1: Write failing model message test**

Add to `neurosploit-go/internal/models/models_test.go`:

```go
func TestMessagesFromSystemUserKeepsStablePrefixSeparate(t *testing.T) {
	msgs := MessagesFromSystemUser("stable system", "dynamic user")
	if len(msgs) != 2 {
		t.Fatalf("len = %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "stable system" {
		t.Fatalf("bad system message: %+v", msgs[0])
	}
	if msgs[1].Role != "user" || msgs[1].Content != "dynamic user" {
		t.Fatalf("bad user message: %+v", msgs[1])
	}
}
```

- [ ] **Step 2: Add message types and wrappers**

In `neurosploit-go/internal/models/models.go`, add near `ModelRef`:

```go
type ChatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	Name       string         `json:"name,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []map[string]any `json:"tool_calls,omitempty"`
}

func MessagesFromSystemUser(system, user string) []ChatMessage {
	return []ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}
```

Add a new method below `ChatWithTools`:

```go
func (c ChatClient) ChatMessagesWithTools(ctx context.Context, m ModelRef, messages []ChatMessage, tools []map[string]any) (string, error) {
	if len(messages) == 0 {
		return "", fmt.Errorf("messages required")
	}
	system, user := flattenMessages(messages)
	return c.ChatWithTools(ctx, m, system, user, tools)
}

func flattenMessages(messages []ChatMessage) (string, string) {
	var system []string
	var user []string
	for _, msg := range messages {
		switch msg.Role {
		case "system":
			system = append(system, msg.Content)
		default:
			if msg.Content != "" {
				user = append(user, strings.ToUpper(msg.Role)+": "+msg.Content)
			}
		}
	}
	return strings.Join(system, "\n\n"), strings.Join(user, "\n\n")
}
```

This keeps compatibility first; a later implementation can send native message arrays directly in the request body.

- [ ] **Step 3: Extend pool interface and implementation**

In `neurosploit-go/internal/pool/pool.go`, add to `ChatClient` interface:

```go
	ChatMessagesWithTools(ctx context.Context, m models.ModelRef, messages []models.ChatMessage, tools []map[string]any) (string, error)
```

Add to `ModelPool`:

```go
func (p *ModelPool) CompleteMessagesWithTools(label string, task Task, messages []models.ChatMessage, tools []map[string]any) (models.ModelRef, string, error) {
	system, user := models.MessagesToSystemUser(messages)
	return p.CompleteWithTools(label, task, system, user, tools)
}
```

If `MessagesToSystemUser` does not exist, expose `flattenMessages` as:

```go
func MessagesToSystemUser(messages []ChatMessage) (string, string) {
	return flattenMessages(messages)
}
```

- [ ] **Step 4: Update pool fake client**

In `neurosploit-go/internal/pool/pool_test.go`, add to `fakeClient`:

```go
func (f fakeClient) ChatMessagesWithTools(ctx context.Context, m models.ModelRef, messages []models.ChatMessage, tools []map[string]any) (string, error) {
	system, user := models.MessagesToSystemUser(messages)
	return f.Chat(ctx, m, system, user)
}
```

- [ ] **Step 5: Run model and pool tests**

Run:

```bash
cd neurosploit-go
go test ./internal/models ./internal/pool -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add neurosploit-go/internal/models/models.go neurosploit-go/internal/models/models_test.go neurosploit-go/internal/pool/pool.go neurosploit-go/internal/pool/pool_test.go
git commit -m "feat: add structured chat message compatibility"
```

---

### Task 7: Prompt Doctrine and Tool Recipe Docs

**Files:**
- Modify: `neurosploit-go/internal/toolloop/toolloop.go`
- Modify: `neurosploit-go/internal/pipeline/prompt.go`
- Create: `docs/TOOL_RECIPES.md`

- [ ] **Step 1: Update tool prompt rules**

In `renderToolPrompt` in `neurosploit-go/internal/toolloop/toolloop.go`, replace the `RULES` block with:

```go
	b.WriteString("RULES:\n")
	b.WriteString("1. Only use tools you have been given.\n")
	b.WriteString("2. Use the parameter names and formats exactly as documented; host-only tools do not accept full URLs.\n")
	b.WriteString("3. Wait for the observation after each tool call before deciding the next step.\n")
	b.WriteString("4. If you receive VALIDATION_ERROR, repair the exact parameter named in the observation and retry once with corrected arguments.\n")
	b.WriteString("5. When you have enough evidence, reply with your final answer only.\n")
```

- [ ] **Step 2: Add concise schema-backed examples to prompt doctrine**

In `neurosploit-go/internal/pipeline/prompt.go`, append this paragraph inside `toolDoctrine` before `Use only what is installed`:

```go
			"- Tool argument shapes: host scanners (`nmap`, `rustscan`, `naabu`) take host/IP only, not `http://` URLs; web tools (`katana`, `httpx`, `nuclei`, `curl`) take full URLs; fuzzers require an explicit `FUZZ` marker where applicable.\n"+
```

- [ ] **Step 3: Add recipe authoring documentation**

Create `docs/TOOL_RECIPES.md`:

```markdown
# Tool Recipe Authoring

Tool recipes live in `toolsdata/**/*.yaml`. They are used both to build command
argv and to validate model tool calls before execution.

## Semantic Parameters

Use `target_format` on target-like parameters:

| Format | Use for | Example |
|---|---|---|
| `host_or_ip` | host scanners such as `nmap` | `example.com` |
| `url` | web tools such as `katana` and `curl` | `https://example.com/path` |
| `url_with_fuzz` | fuzzers such as `ffuf` | `https://example.com/FUZZ` |
| `domain` | DNS/OSINT tools | `example.com` |
| `cidr` | network range tools | `192.0.2.0/24` |

Use `min` and `max` for integers, `enum` for closed sets, and `pattern` for
compact string validation such as port lists.

## Additional Args

Prefer typed parameters over `additional_args`. If a recipe keeps
`additional_args`, declare `allowed_flags` and keep `allow_shell: false` unless
there is a reviewed reason to permit shell syntax.

## Examples

```yaml
- name: target
  type: string
  description: Hostname or IP to scan.
  required: true
  position: 0
  format: positional
  target_format: host_or_ip

- name: depth
  type: int
  description: Crawl depth.
  default: 3
  flag: -d
  format: combined
  min: 1
  max: 10
```
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
cd neurosploit-go
go test ./internal/toolloop ./internal/pipeline -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add neurosploit-go/internal/toolloop/toolloop.go neurosploit-go/internal/pipeline/prompt.go docs/TOOL_RECIPES.md
git commit -m "docs: document strict tool recipe contracts"
```

---

### Task 8: Final Verification

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run formatting**

Run:

```bash
cd neurosploit-go
gofmt -w internal/tools internal/toolloop internal/pipeline internal/models internal/pool
```

Expected: no output.

- [ ] **Step 2: Run vet**

Run:

```bash
cd neurosploit-go
go vet ./...
```

Expected: no output and exit code 0.

- [ ] **Step 3: Run full tests**

Run:

```bash
cd neurosploit-go
go test ./... -timeout 30s
```

Expected: all packages pass.

- [ ] **Step 4: Run release build check**

Run:

```bash
cd neurosploit-go
make build-release
```

Expected: embedded-agent release build completes successfully.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --stat HEAD
```

Expected: only intentional strict tool-loop implementation files are modified.

- [ ] **Step 6: Commit final formatting or verification fixes**

If Step 1 changed files or Step 5 shows small verification fixes, run:

```bash
git add neurosploit-go docs toolsdata
git commit -m "chore: finalize strict tool loop"
```

Expected: commit succeeds, or there is nothing to commit.

---

## Self-Review

Spec coverage:

- Semantic tool contracts: Tasks 1 and 3.
- Validation and safe normalization: Task 2.
- Repair observations and repeated-invalid guard: Task 4.
- Bootstrap/subscription recon reuse: Task 5.
- Message transcript compatibility and prompt cache shape: Task 6.
- Prompt examples and recipe docs: Task 7.
- CI verification: Task 8.

Review passed. Type names introduced in early tasks are reused consistently: `ValidationIssue`, `ValidationWarning`, `ValidationResult`, `ValidateCall`, `FormatValidationIssues`, `ChatMessage`, and `MessagesFromSystemUser`.
