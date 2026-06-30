package grounding

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Result is the verdict of grounding a single finding.
type Result struct {
	OK     bool
	Kind   string
	Reason string
}

// markers are substrings that strongly suggest a finding's evidence is a raw
// tool receipt rather than an LLM paraphrase.
var empiricalMarkers = []string{
	"http/", "status", "200", "301", "302", "401", "403", "500",
	"set-cookie", "location:", "content-type", "<html", "<script",
	"server:", "x-", "alert(", "uid=", "root:", "sql", "error", "stack",
	"callback", "oob", "collaborator", "$ ", "# ", "curl", "nmap",
}

// looksEmpirical reports whether the evidence looks like raw tool output.
func looksEmpirical(f *types.Finding) bool {
	if len(f.Evidence) < 24 {
		return false
	}
	lower := strings.ToLower(f.Evidence)
	found := 0
	for _, m := range empiricalMarkers {
		if strings.Contains(lower, m) {
			found++
			if found >= 2 {
				return true
			}
		}
	}
	return false
}

// looksSymbolic reports whether a white-box finding references a source
// location or quotes source tokens that appear in the reviewed context.
func looksSymbolic(f *types.Finding, context string) bool {
	if fileLineMatch(f.Endpoint, context) {
		return true
	}
	return tokenMatches(f.Evidence, context)
}

// fileLineMatch checks if the endpoint has the form file:line and the file's
// basename appears in context.
func fileLineMatch(endpoint, context string) bool {
	idx := strings.LastIndex(endpoint, ":")
	if idx < 0 {
		return false
	}
	file := endpoint[:idx]
	line := endpoint[idx+1:]
	if file == "" || line == "" {
		return false
	}
	for _, r := range line {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	base := filepath.Base(file)
	if base == "" {
		return false
	}
	return strings.Contains(strings.ToLower(context), strings.ToLower(base))
}

// tokenMatches checks that at least two whitespace-separated tokens of length
// greater than 4 from the first six words of evidence appear in context.
func tokenMatches(evidence, context string) bool {
	if strings.TrimSpace(evidence) == "" {
		return false
	}
	ctxLower := strings.ToLower(context)
	words := strings.Fields(evidence)
	if len(words) > 6 {
		words = words[:6]
	}
	matches := 0
	for _, w := range words {
		if len(w) > 4 && strings.Contains(ctxLower, strings.ToLower(w)) {
			matches++
			if matches >= 2 {
				return true
			}
		}
	}
	return false
}

// Ground evaluates whether a finding has a valid tool receipt.
// For black-box runs the receipt is empirical (raw tool output); for white-box
// runs it is symbolic (a source location or code quote present in context).
func Ground(f *types.Finding, context string, whitebox bool) Result {
	if whitebox && strings.TrimSpace(context) != "" {
		if looksSymbolic(f, context) {
			return Result{OK: true, Kind: "symbolic", Reason: ""}
		}
		return Result{
			OK:     false,
			Kind:   "missing",
			Reason: "no symbolic receipt for " + f.Endpoint,
		}
	}
	if looksEmpirical(f) {
		return Result{OK: true, Kind: "empirical", Reason: ""}
	}
	return Result{
		OK:     false,
		Kind:   "missing",
		Reason: "no tool receipt for " + f.Endpoint,
	}
}

// Gate applies the grounding gate to a set of findings. Ungrounded findings
// are flagged with "receipt_missing" in their Votes field, demoted to
// unvalidated, and then filtered out. It returns the kept findings and the
// number of demoted findings.
func Gate(findings []types.Finding, context string, whitebox bool) ([]types.Finding, int) {
	demoted := 0
	for i := range findings {
		r := Ground(&findings[i], context, whitebox)
		if r.OK {
			continue
		}
		findings[i].Validated = false
		findings[i].Votes += " · receipt_missing"
		demoted++
	}

	kept := findings[:0]
	for _, f := range findings {
		if f.Validated {
			kept = append(kept, f)
		}
	}
	return kept, demoted
}
