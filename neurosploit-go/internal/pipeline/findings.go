package pipeline

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func parseStringArray(text string) []string {
	a := strings.Index(text, "[")
	b := strings.LastIndex(text, "]")
	if a < 0 || b <= a {
		return nil
	}
	var names []string
	if err := json.Unmarshal([]byte(text[a:b+1]), &names); err != nil {
		return nil
	}
	return names
}

func extractFindings(text, agent string) []types.Finding {
	slice := extractJSONSlice(text)
	if slice == "" {
		return nil
	}
	var val any
	if err := json.Unmarshal([]byte(slice), &val); err != nil {
		return nil
	}
	var items []map[string]any
	switch v := val.(type) {
	case []any:
		for _, it := range v {
			if o, ok := it.(map[string]any); ok {
				items = append(items, o)
			}
		}
	case map[string]any:
		items = []map[string]any{v}
	default:
		return nil
	}
	var out []types.Finding
	for _, o := range items {
		title := fieldStr(o, "title")
		if title == "" {
			continue
		}
		id := fieldStr(o, "id")
		if id == "" {
			runes := []rune(title)
			if len(runes) > 12 {
				runes = runes[:12]
			}
			id = fmt.Sprintf("%s-%s", agent, string(runes))
		}
		f := types.Finding{
			ID:          id,
			Agent:       agent,
			Title:       title,
			Severity:    normSev(fieldStr(o, "severity")),
			CWE:         fieldStr(o, "cwe"),
			CVSS:        fieldStr(o, "cvss"),
			Endpoint:    fieldStr(o, "endpoint"),
			Payload:     fieldStr(o, "payload"),
			Evidence:    fieldStr(o, "evidence"),
			Impact:      fieldStr(o, "impact"),
			Remediation: fieldStr(o, "remediation"),
			Confidence:  fieldConf(o["confidence"]),
			ChainsFrom:  []string{},
		}
		if isNegativeFinding(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// isNegativeFinding drops probe logs and confirmed-absence reports masquerading as findings.
func isNegativeFinding(f types.Finding) bool {
	title := strings.ToLower(strings.TrimSpace(f.Title))
	evidence := strings.ToLower(f.Evidence)
	impact := strings.ToLower(f.Impact)
	hay := title + " " + evidence + " " + impact

	if strings.HasPrefix(title, "test for ") {
		return true
	}
	for _, p := range []string{
		"no exposed",
		"not exposed",
		"no backup file",
		"no evidence of exposed",
		"no evidence of ",
		"not a finding",
		"not detected",
		"no action required",
		"baseline established",
		"for subsequent",
		"recon only",
		"reconnaissance only",
		"nothing to confirm",
		"no graphql endpoint",
		"endpoint does not exist",
		"confirmed absent",
		"negative test",
		"probe result: not",
	} {
		if strings.Contains(hay, p) {
			return true
		}
	}
	return false
}

func extractJSONSlice(text string) string {
	text = stripCodeFences(text)
	a := strings.Index(text, "[")
	b := strings.LastIndex(text, "]")
	if a >= 0 && b > a {
		return text[a : b+1]
	}
	a = strings.Index(text, "{")
	b = strings.LastIndex(text, "}")
	if a >= 0 && b > a {
		return text[a : b+1]
	}
	return ""
}

// stripCodeFences removes markdown ``` / ```json wrappers from model output.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if nl := strings.Index(s, "\n"); nl >= 0 {
			s = strings.TrimSpace(s[nl+1:])
		} else {
			rest := strings.TrimPrefix(s, "```")
			rest = strings.TrimLeft(rest, " \t")
			if sp := strings.IndexByte(rest, ' '); sp >= 0 && sp < 16 {
				rest = strings.TrimSpace(rest[sp+1:])
			}
			s = rest
		}
	}
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSpace(strings.TrimSuffix(s, "```"))
	}
	return strings.TrimSpace(s)
}

func fieldStr(o map[string]any, k string) string {
	v, ok := o[k]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

func fieldConf(v any) float64 {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		s := strings.TrimSpace(t)
		if f, err := parseFloat(s); err == nil {
			return f
		}
		lower := strings.ToLower(s)
		switch {
		case strings.Contains(lower, "critical") || strings.Contains(lower, "very high"):
			return 0.97
		case strings.Contains(lower, "high"):
			return 0.9
		case strings.Contains(lower, "med"):
			return 0.6
		case strings.Contains(lower, "low"):
			return 0.3
		}
	}
	return 0
}

func parseFloat(s string) (float64, error) {
	return json.Number(s).Float64()
}

func dedupFindings(v []types.Finding) []types.Finding {
	sort.Slice(v, func(i, j int) bool {
		return v[i].Confidence > v[j].Confidence
	})
	seen := make(map[string]bool)
	var out []types.Finding
	for _, f := range v {
		titleKey := f.Title
		runes := []rune(strings.ToLower(titleKey))
		if len(runes) > 40 {
			runes = runes[:40]
		}
		key := fmt.Sprintf("%s|%s|%s", strings.ToLower(f.CWE), strings.ToLower(f.Endpoint), string(runes))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func normSev(s string) string {
	switch strings.ToLower(s) {
	case "":
		return "Info"
	default:
		if strings.HasPrefix(strings.ToLower(s), "crit") {
			return "Critical"
		}
		if strings.HasPrefix(strings.ToLower(s), "high") {
			return "High"
		}
		if strings.HasPrefix(strings.ToLower(s), "med") {
			return "Medium"
		}
		if strings.HasPrefix(strings.ToLower(s), "low") {
			return "Low"
		}
		return "Info"
	}
}
