package pipeline

import (
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
)

func TestHeuristicSelectBaseline(t *testing.T) {
	ranked := []agents.Agent{
		{Name: "sqli_error", Title: "SQLi Error Agent"},
		{Name: "custom_agent", Title: "Custom Agent"},
	}
	got := heuristicSelect(ranked, "{}", "", 1)
	if len(got) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(got))
	}
	if got[0].Name != "sqli_error" {
		t.Fatalf("expected sqli_error, got %s", got[0].Name)
	}
}

func TestHeuristicSelectReconSignal(t *testing.T) {
	ranked := []agents.Agent{
		{Name: "graphql_introspection", Title: "GraphQL Agent"},
		{Name: "sqli_error", Title: "SQLi Error Agent"},
	}
	got := heuristicSelect(ranked, `{"tech":"graphql"}`, "", 2)
	if len(got) < 1 || got[0].Name != "graphql_introspection" {
		t.Fatalf("expected graphql first, got %v", agentNames(got))
	}
}

func TestHeuristicSelectFocus(t *testing.T) {
	ranked := []agents.Agent{
		{Name: "sqli_error", Title: "SQLi Error Agent"},
		{Name: "xss_reflected", Title: "XSS Reflected Agent"},
	}
	got := heuristicSelect(ranked, "{}", "focus on sqli injection", 1)
	if len(got) != 1 || got[0].Name != "sqli_error" {
		t.Fatalf("got %v", agentNames(got))
	}
}
