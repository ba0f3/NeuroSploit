package grounding

import (
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestGateKeepsEmpiricalReceipt(t *testing.T) {
	findings := []types.Finding{
		{
			ID:       "emp-1",
			Endpoint: "http://example.com/login",
			Evidence: "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html",
			Votes:    "",
		},
	}

	kept, demoted := Gate(findings, "", false)
	if demoted != 0 {
		t.Fatalf("expected 0 demoted, got %d", demoted)
	}
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept finding, got %d", len(kept))
	}
	if !kept[0].Validated {
		t.Fatalf("expected kept finding to remain validated")
	}
}

func TestGateDemotesParaphraseOnly(t *testing.T) {
	findings := []types.Finding{
		{
			ID:       "para-1",
			Endpoint: "http://example.com/login",
			Evidence: "the app might be vulnerable",
			Votes:    "",
		},
	}

	kept, demoted := Gate(findings, "", false)
	if demoted != 1 {
		t.Fatalf("expected 1 demoted, got %d", demoted)
	}
	if len(kept) != 0 {
		t.Fatalf("expected 0 kept findings, got %d", len(kept))
	}
}

func TestGateWhiteboxSymbolicMatch(t *testing.T) {
	findings := []types.Finding{
		{
			ID:       "sym-1",
			Endpoint: "main.go:42",
			Evidence: "...",
			Votes:    "",
		},
	}

	kept, demoted := Gate(findings, "analysis of main.go", true)
	if demoted != 0 {
		t.Fatalf("expected 0 demoted, got %d", demoted)
	}
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept finding, got %d", len(kept))
	}
	if !kept[0].Validated {
		t.Fatalf("expected kept finding to remain validated")
	}
}

func TestGateWhiteboxSymbolicMiss(t *testing.T) {
	findings := []types.Finding{
		{
			ID:       "sym-2",
			Endpoint: "main.go:42",
			Evidence: "...",
			Votes:    "",
		},
	}

	kept, demoted := Gate(findings, "analysis of other.go", true)
	if demoted != 1 {
		t.Fatalf("expected 1 demoted, got %d", demoted)
	}
	if len(kept) != 0 {
		t.Fatalf("expected 0 kept findings, got %d", len(kept))
	}
}
