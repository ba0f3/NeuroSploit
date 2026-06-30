package report

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestHTMLContainsFinding(t *testing.T) {
	html := HTML("http://example.test", []types.Finding{{
		Title: "SQLi", Severity: "Critical", Agent: "sqli", Endpoint: "/x",
	}})
	if !strings.Contains(html, "SQLi") || !strings.Contains(html, "NeuroSploit") {
		t.Fatalf("HTML missing expected content")
	}
}

func TestHTMLEmptyFindings(t *testing.T) {
	html := HTML("http://example.test", nil)
	if !strings.Contains(html, "No validated findings") {
		t.Fatalf("expected empty-state chip")
	}
}
