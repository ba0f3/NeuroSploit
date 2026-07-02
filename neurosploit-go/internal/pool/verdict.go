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

// QuorumConfirmedToolVerified applies a lower bar when sqlmap proof + log path are present.
func QuorumConfirmedToolVerified(severity string, yes, total int) bool {
	if total == 0 {
		return false
	}
	s := strings.ToLower(severity)
	if strings.HasPrefix(s, "crit") {
		return yes >= 1
	}
	return QuorumConfirmed(severity, yes, total)
}

// VoteDetail is one validator model's parsed verdict.
type VoteDetail struct {
	Model   string
	Verdict string
	Reason  string
}

func VerdictLabel(v Verdict) string {
	switch v {
	case VerdictConfirmed:
		return "confirmed"
	case VerdictRejected:
		return "rejected"
	default:
		return "unclear"
	}
}

// ExtractVoteReason pulls a short reason string from validator JSON when present.
func ExtractVoteReason(text string) string {
	lower := strings.ToLower(text)
	for _, key := range []string{`"reason":"`, `"reason": "`} {
		if i := strings.Index(lower, key); i >= 0 {
			rest := text[i+len(key):]
			if j := strings.Index(rest, `"`); j > 0 {
				return strings.TrimSpace(rest[:j])
			}
		}
	}
	return ""
}
