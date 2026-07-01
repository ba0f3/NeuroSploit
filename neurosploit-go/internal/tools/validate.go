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
