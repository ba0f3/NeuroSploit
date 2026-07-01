package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/report"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func persist(cfg types.RunConfig, recon, transcript, toolLog string, findings []types.Finding) []string {
	if cfg.Workdir == nil {
		return nil
	}
	dir := *cfg.Workdir
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil
	}
	var written []string
	put := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err == nil {
			written = append(written, p)
		}
	}
	put("recon.json", recon)
	put("recon.md", fmt.Sprintf("# Recon — %s\n\n```json\n%s\n```\n", cfg.Target, recon))
	if toolLog != "" {
		put("recon_tools.md", fmt.Sprintf("# Tool log — %s\n\n%s", cfg.Target, toolLog))
	}
	if transcript != "" {
		put("exploitation.md", fmt.Sprintf("# Agent transcript — %s\n\n%s", cfg.Target, transcript))
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		data = []byte("[]")
	}
	put("findings.json", string(data))
	put("findings.md", findingsMD(cfg.Target, findings))
	put("report.html", report.HTML(cfg.Target, findings))
	put("status.json", `{"status":"complete"}`)
	return written
}

func findingsMD(target string, findings []types.Finding) string {
	var s strings.Builder
	fmt.Fprintf(&s, "# NeuroSploit findings — %s\n\n%d validated finding(s).\n", target, len(findings))
	for i, f := range findings {
		fmt.Fprintf(&s, "\n## %d. [%s] %s\n- agent: `%s`  CWE: %s  CVSS: %s  votes: %s  confidence: %.2f\n- endpoint: %s\n\n**Payload**\n```\n%s\n```\n\n**Evidence**\n%s\n\n**Impact:** %s\n\n**Remediation:** %s\n",
			i+1, f.Severity, f.Title, f.Agent, f.CWE, f.CVSS, f.Votes, f.Confidence, f.Endpoint, f.Payload, f.Evidence, f.Impact, f.Remediation)
	}
	return s.String()
}

func transcriptOf(raw []exploitResult) string {
	var parts []string
	for _, r := range raw {
		parts = append(parts, fmt.Sprintf("## %s (%d candidate)\n\n%s\n", r.name, len(r.findings), r.text))
	}
	return strings.Join(parts, "\n")
}
