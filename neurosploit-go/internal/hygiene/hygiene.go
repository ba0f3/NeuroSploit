package hygiene

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Hedging words that signal an impact was described but not demonstrated
// (English + Portuguese, since engagements are bilingual).
var WEASEL = []string{
	"could ", "may ", "might ", "potential", "possible", "possibly", "teóric", "theoret",
	"poderia", "possív", "potencial", "if the ", "caso o", "caso a", "would allow", "permitiria",
}

// EXPOSURE_CWES lists CWEs that indicate information disclosure / exposure
// rather than a demonstrated exploit.
var EXPOSURE_CWES = []string{"200", "527", "538", "942", "497", "209", "548", "16"}

// ExposureKeywords are title substrings used to classify a finding as exposure.
var ExposureKeywords = []string{
	"disclosure", "exposed", "exposi", "exposure", "catalog", "catálogo", "cors",
	"banner", "version", "versão", "header", "cabeçalho", ".git", "enumerat",
	"fingerprint", "wsdl", "swagger", "missing security", "outdated", "eol",
}

func hostOf(endpoint string) string {
	s := strings.TrimSpace(endpoint)
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "?"); idx != -1 {
		s = s[:idx]
	}
	return strings.ToLower(s)
}

func sevRank(severity string) int {
	s := strings.ToLower(severity)
	switch {
	case strings.HasPrefix(s, "crit"):
		return 4
	case strings.HasPrefix(s, "high"):
		return 3
	case strings.HasPrefix(s, "med"):
		return 2
	case strings.HasPrefix(s, "low"):
		return 1
	default:
		return 0
	}
}

func short(s string) string {
	runes := []rune(s)
	if len(runes) <= 64 {
		return s
	}
	return string(runes[:64])
}

// evidenceIsHedged reports whether the evidence (or related title/impact text)
// contains any WEASEL word as a substring.
func evidenceIsHedged(title, impact, evidence string) bool {
	blob := strings.ToLower(fmt.Sprintf("%s %s %s", title, impact, evidence))
	for _, w := range WEASEL {
		if strings.Contains(blob, w) {
			return true
		}
	}
	return false
}

// looksUnproven reads as unproven: hedged or thin evidence AND no concrete payload.
func looksUnproven(f *types.Finding) bool {
	hedged := evidenceIsHedged(f.Title, f.Impact, f.Evidence)
	weakEv := utf8.RuneCountInString(strings.TrimSpace(f.Evidence)) < 40
	noPayload := strings.TrimSpace(f.Payload) == ""
	return (hedged || weakEv) && noPayload
}

// isExposure reports whether a finding exposes something (recon/disclosure)
// rather than being an exploit with demonstrated impact.
func isExposure(f *types.Finding) bool {
	cwe := strings.ToLower(f.CWE)
	title := strings.ToLower(f.Title)
	for _, c := range EXPOSURE_CWES {
		if strings.Contains(cwe, c) {
			return true
		}
	}
	for _, k := range ExposureKeywords {
		if strings.Contains(title, k) {
			return true
		}
	}
	return false
}

// classOf returns a normalized hygiene class for consolidation advice.
func classOf(f *types.Finding) string {
	t := strings.ToLower(f.Title)
	switch {
	case strings.Contains(t, "header") || strings.Contains(t, "cabeçalho"):
		return "missing-security-headers"
	case strings.Contains(t, "clickjack") || strings.Contains(t, "frame"):
		return "clickjacking"
	case strings.Contains(t, "hsts") || strings.Contains(t, "strict-transport"):
		return "missing-hsts"
	case strings.Contains(t, "cookie"):
		return "cookie-flags"
	case strings.Contains(t, "tls") || strings.Contains(t, "ssl"):
		return "weak-tls"
	case strings.Contains(t, "cors"):
		return "cors-misconfig"
	case strings.Contains(t, "version") || strings.Contains(t, "versão") ||
		strings.Contains(t, "banner") || strings.Contains(t, "eol") || strings.Contains(t, "outdated"):
		return "version-disclosure"
	default:
		return "information-disclosure"
	}
}

// Calibrate caps inflated, unproven High/Critical findings to Medium. Returns advisories.
func Calibrate(findings *[]types.Finding) []string {
	var notes []string
	for i := range *findings {
		f := &(*findings)[i]
		if sevRank(f.Severity) >= 3 && looksUnproven(f) {
			old := f.Severity
			f.Severity = "Medium"
			if f.Confidence > 0.5 {
				f.Confidence = 0.5
			}
			low := strings.ToLower(f.Title)
			if !strings.Contains(low, "potential") && !strings.Contains(low, "potencial") {
				f.Title = fmt.Sprintf("%s (potential — impact not demonstrated)", f.Title)
			}
			notes = append(notes, fmt.Sprintf(
				"severity calibrated: \"%s\" %s → Medium (impact not demonstrated)",
				short(f.Title), old,
			))
		}
	}
	return notes
}

// DepthAudit flags exposures on a host with no real exploit on the same host.
func DepthAudit(findings []types.Finding) []string {
	exploited := make(map[string]struct{})
	for i := range findings {
		f := &findings[i]
		if !isExposure(f) && sevRank(f.Severity) >= 2 {
			exploited[hostOf(f.Endpoint)] = struct{}{}
		}
	}
	var notes []string
	for i := range findings {
		f := &findings[i]
		if isExposure(f) {
			if _, ok := exploited[hostOf(f.Endpoint)]; !ok {
				notes = append(notes, fmt.Sprintf(
					"depth gap: \"%s\" exposed but not exploited — USE it (call the endpoint / decode the artifact / log in / hit the dev host) to prove impact, or down-rate to a lead",
					short(f.Title),
				))
			}
		}
	}
	if len(notes) > 8 {
		notes = notes[:8]
	}
	return notes
}

// HygieneSummary advises consolidating hygiene classes that repeat across multiple assets.
func HygieneSummary(findings []types.Finding) []string {
	groups := make(map[string]map[string]struct{})
	for i := range findings {
		f := &findings[i]
		if isExposure(f) {
			class := classOf(f)
			if groups[class] == nil {
				groups[class] = make(map[string]struct{})
			}
			groups[class][hostOf(f.Endpoint)] = struct{}{}
		}
	}
	var notes []string
	for class, hosts := range groups {
		if len(hosts) > 1 {
			notes = append(notes, fmt.Sprintf(
				"hygiene: '%s' affects %d assets — consolidate into ONE finding with an affected-asset table (don't inflate the count one-per-host)",
				class, len(hosts),
			))
		}
	}
	return notes
}

