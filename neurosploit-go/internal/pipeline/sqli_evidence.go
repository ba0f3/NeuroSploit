package pipeline

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

const (
	voteEvidenceLimit   = 8000
	sqliToolLoopMaxIter = 8
)

func sqlmapHarnessArgs(targetURL string) map[string]any {
	return map[string]any{
		"target":        targetURL,
		"batch":         true,
		"flush_session": true,
		"fresh_queries": true,
	}
}

// extractSQLMapProof pulls the injectable-parameter block from sqlmap stdout.
func extractSQLMapProof(out string) string {
	low := strings.ToLower(out)
	start := strings.Index(low, "parameter:")
	if start < 0 {
		start = strings.Index(low, "sql injection")
	}
	if start < 0 {
		return truncateOut(out, 1200)
	}
	chunk := out[start:]
	if idx := strings.Index(chunk, "\n\n[*] ending"); idx > 0 {
		chunk = chunk[:idx]
	}
	if idx := strings.Index(chunk, "\n\ndo you want to exploit"); idx > 0 {
		chunk = chunk[:idx]
	}
	return strings.TrimSpace(chunk)
}

func buildSQLMapEvidence(out, logPath string) string {
	var b strings.Builder
	if proof := extractSQLMapProof(out); proof != "" {
		b.WriteString(proof)
	}
	if logPath != "" {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "Full log: %s", logPath)
	}
	if b.Len() == 0 {
		return truncateOut(out, voteEvidenceLimit)
	}
	ev := b.String()
	if len(ev) > voteEvidenceLimit {
		return ev[:voteEvidenceLimit] + "\n... [truncated]"
	}
	return ev
}

func sqlmapProofVerified(evidence string) bool {
	low := strings.ToLower(evidence)
	return strings.Contains(evidence, "Parameter:") &&
		strings.Contains(low, "type:") &&
		strings.Contains(low, "payload:") &&
		strings.Contains(evidence, "Full log:")
}

func parseSQLMapFinding(out, targetURL, agent, logPath string) *types.Finding {
	low := strings.ToLower(out)
	if !strings.Contains(low, "parameter:") {
		if !strings.Contains(low, "sql injection") {
			return nil
		}
	}
	if strings.Contains(low, "not injectable") ||
		strings.Contains(low, "all tested parameters do not appear to be injectable") ||
		strings.Contains(low, "might not be injectable") {
		return nil
	}
	proof := extractSQLMapProof(out)
	if proof == "" || !strings.Contains(strings.ToLower(proof), "parameter:") {
		return nil
	}
	param, technique := sqlmapTitleParts(proof)
	title := "SQL Injection (sqlmap confirmed)"
	if param != "" {
		if technique != "" {
			title = fmt.Sprintf("%s SQLi in %s", technique, param)
		} else {
			title = fmt.Sprintf("SQL Injection in %s", param)
		}
	}
	f := types.DefaultFinding()
	f.Agent = agent
	f.Title = title
	f.Severity = "Critical"
	f.CWE = "CWE-89"
	f.Endpoint = targetURL
	f.Payload = firstSQLMapPayload(proof)
	f.Evidence = buildSQLMapEvidence(out, logPath)
	f.Impact = "Database query manipulation — sqlmap confirmed injectable parameter with reproducible payloads."
	f.Remediation = "Use parameterized queries; validate and cast numeric inputs."
	f.Confidence = 0.9
	return &f
}

func sqlmapTitleParts(proof string) (param, technique string) {
	for _, line := range strings.Split(proof, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "parameter:") {
			param = strings.TrimSpace(strings.TrimPrefix(line, "Parameter:"))
			param = strings.TrimSpace(strings.TrimPrefix(param, "parameter:"))
			if i := strings.Index(param, "("); i > 0 {
				param = strings.TrimSpace(param[:i])
			}
		}
		if strings.HasPrefix(low, "type:") {
			technique = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			technique = strings.TrimSpace(strings.TrimPrefix(technique, "type:"))
			if i := strings.Index(technique, "-"); i > 0 {
				technique = strings.TrimSpace(technique[:i])
			}
		}
	}
	return param, technique
}

func firstSQLMapPayload(proof string) string {
	for _, line := range strings.Split(proof, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "payload:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return "sqlmap automated probe"
}

func endpointSlug(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path == "" {
		return u
	}
	return parsed.Path
}
