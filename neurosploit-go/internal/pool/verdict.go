package pool

import (
	"strings"
	"unicode"
)

// Verdict is a validator's verdict on a candidate finding.
type Verdict int

const (
	VerdictConfirmed Verdict = iota
	VerdictRejected
	VerdictUnclear
)

// ParseVerdict robustly parses a validator reply. Whitespace-insensitive JSON scan;
// explicit rejection wins; ambiguous replies are Unclear (not counted as confirmed).
func ParseVerdict(text string) Verdict {
	lower := strings.ToLower(text)
	var dense strings.Builder
	for _, c := range lower {
		if !unicode.IsSpace(c) {
			dense.WriteRune(c)
		}
	}
	d := dense.String()

	rejected := []string{
		`"verdict":"rejected"`, `"verdict":"reject"`, "verdict:rejected",
		`"is_real":false`, `"isreal":false`, `"confirmed":false`, `"real":false`,
		`"exploitable":false`, `"valid":false`,
	}
	for _, k := range rejected {
		if strings.Contains(d, k) {
			return VerdictRejected
		}
	}

	confirmed := []string{
		`"verdict":"confirmed"`, "verdict:confirmed",
		`"is_real":true`, `"isreal":true`, `"confirmed":true`, `"real":true`,
		`"exploitable":true`, `"valid":true`,
	}
	for _, k := range confirmed {
		if strings.Contains(d, k) {
			return VerdictConfirmed
		}
	}

	if strings.HasPrefix(strings.TrimSpace(lower), "yes") {
		return VerdictConfirmed
	}
	return VerdictUnclear
}

// QuorumConfirmed applies severity-aware confirmation quorum. High/Critical with
// total >= 2 need >=2/3 agreement; lower severities need strict majority.
func QuorumConfirmed(severity string, yes, total int) bool {
	if total == 0 {
		return false
	}
	s := strings.ToLower(severity)
	high := strings.HasPrefix(s, "crit") || strings.HasPrefix(s, "high")
	if high && total >= 2 {
		return yes*3 >= total*2
	}
	return yes*2 > total
}
