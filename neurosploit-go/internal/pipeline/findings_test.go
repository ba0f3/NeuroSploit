package pipeline

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestParseStringArray(t *testing.T) {
	got := parseStringArray(`Here are agents: ["sqli_error", "xss_reflected"] done`)
	if len(got) != 2 || got[0] != "sqli_error" {
		t.Fatalf("got %v", got)
	}
}

func TestExtractFindings(t *testing.T) {
	text := `[{"title":"SQLi","severity":"critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200","confidence":0.9}]`
	got := extractFindings(text, "sqli_error")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != "Critical" || got[0].Title != "SQLi" {
		t.Fatalf("got %+v", got[0])
	}
}

func TestExtractFindingsConfidenceString(t *testing.T) {
	text := `[{"title":"X","severity":"high","confidence":"High"}]`
	got := extractFindings(text, "x")
	if len(got) != 1 || got[0].Confidence != 0.9 {
		t.Fatalf("got %+v", got[0])
	}
}

func TestDedupFindings(t *testing.T) {
	in := []types.Finding{
		{Title: "A", CWE: "CWE-1", Endpoint: "/a", Confidence: 0.5},
		{Title: "A", CWE: "CWE-1", Endpoint: "/a", Confidence: 0.9},
	}
	got := dedupFindings(in)
	if len(got) != 1 || got[0].Confidence != 0.9 {
		t.Fatalf("got %+v", got)
	}
}

func TestNormSev(t *testing.T) {
	cases := map[string]string{
		"critical": "Critical",
		"HIGH":     "High",
		"med":      "Medium",
		"low":      "Low",
		"":         "Info",
		"unknown":  "Info",
	}
	for in, want := range cases {
		if got := normSev(in); got != want {
			t.Fatalf("normSev(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractFindingsSingleObject(t *testing.T) {
	text := `{"title":"One","severity":"low","cwe":"CWE-79"}`
	got := extractFindings(text, "agent")
	if len(got) != 1 || got[0].Title != "One" {
		t.Fatalf("got %+v", got)
	}
}

func TestStripCodeFences(t *testing.T) {
	in := "```json {\"tech\":{\"server\":\"nginx\"}}"
	got := stripCodeFences(in)
	if strings.HasPrefix(got, "```") || !strings.HasPrefix(got, "{") {
		t.Fatalf("stripCodeFences = %q", got)
	}
	fenced := "```json\n{\"a\":1}\n```"
	if stripCodeFences(fenced) != `{"a":1}` {
		t.Fatalf("multiline fence = %q", stripCodeFences(fenced))
	}
}

func TestExtractFindingsFencedJSON(t *testing.T) {
	text := "```json\n[{\"title\":\"SQLi\",\"severity\":\"high\",\"cwe\":\"CWE-89\",\"endpoint\":\"/x\",\"evidence\":\"ok\"}]\n```"
	got := extractFindings(text, "sqli")
	if len(got) != 1 || got[0].Title != "SQLi" {
		t.Fatalf("got %+v", got)
	}
}
