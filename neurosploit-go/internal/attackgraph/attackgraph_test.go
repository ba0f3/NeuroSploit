package attackgraph

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestEnrich(t *testing.T) {
	findings := []types.Finding{
		{CWE: "CWE-89", Confidence: 0.9, Severity: "High"},
	}
	Enrich(&findings)
	f := findings[0]
	if f.OWASP != "A03:2021-Injection" {
		t.Errorf("OWASP = %q, want A03:2021-Injection", f.OWASP)
	}
	if f.MITRE != "T1190" {
		t.Errorf("MITRE = %q, want T1190", f.MITRE)
	}
	if f.Stage != "initial-access" {
		t.Errorf("Stage = %q, want initial-access", f.Stage)
	}
	if f.Exploitability != "trivial" {
		t.Errorf("Exploitability = %q, want trivial", f.Exploitability)
	}
}

func TestEnrichDoesNotOverwrite(t *testing.T) {
	findings := []types.Finding{
		{CWE: "CWE-89", OWASP: "custom", Confidence: 0.9, Severity: "High"},
	}
	Enrich(&findings)
	if findings[0].OWASP != "custom" {
		t.Errorf("OWASP should remain custom, got %q", findings[0].OWASP)
	}
}

func TestMermaid(t *testing.T) {
	findings := []types.Finding{
		{ID: "f1", Title: "SQLi", Severity: "High", OWASP: "A03:2021-Injection", Stage: "initial-access"},
	}
	out := Mermaid(findings)
	if !strings.Contains(out, "flowchart LR") {
		t.Errorf("Mermaid output should contain flowchart LR, got:\n%s", out)
	}
	if !strings.Contains(out, "subgraph") {
		t.Errorf("Mermaid output should contain subgraph, got:\n%s", out)
	}
}

func TestMermaidEmpty(t *testing.T) {
	if got := Mermaid([]types.Finding{}); got != "" {
		t.Errorf("Mermaid([]) = %q, want empty", got)
	}
}

func TestASCIIKillchain(t *testing.T) {
	findings := []types.Finding{
		{ID: "f2", Title: "RCE", Severity: "Critical", MITRE: "T1059", Stage: "execution"},
		{ID: "f3", Title: "Recon", Severity: "Low", MITRE: "T1592", Stage: "recon"},
	}
	out := ASCIIKillchain(findings)
	if !strings.Contains(out, "recon") {
		t.Errorf("ASCII output should contain recon stage, got:\n%s", out)
	}
	if !strings.Contains(out, "execution") {
		t.Errorf("ASCII output should contain execution stage, got:\n%s", out)
	}
	if !strings.Contains(out, "RCE") {
		t.Errorf("ASCII output should contain finding title RCE, got:\n%s", out)
	}
}
