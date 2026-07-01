package chainengine

import (
	"context"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

type mockCaller struct {
	responses []string
	calls     int
}

func (m *mockCaller) RunStage(ctx context.Context, agent agents.Agent, user string) (string, error) {
	if m.calls >= len(m.responses) {
		return "[]", nil
	}
	r := m.responses[m.calls]
	m.calls++
	return r, nil
}

func TestPreconditionsMatch(t *testing.T) {
	confirmed := []types.Finding{{Title: "SQL Injection", CWE: "CWE-89"}}
	if !preconditionsMatch([]string{"sqli", "CWE-89"}, confirmed) {
		t.Fatal("expected sqli precondition to match")
	}
	if preconditionsMatch([]string{"ssrf"}, confirmed) {
		t.Fatal("expected ssrf precondition to miss")
	}
	if !preconditionsMatch(nil, confirmed) {
		t.Fatal("empty preconditions should match")
	}
}

func TestEngineStopsEarly(t *testing.T) {
	caller := &mockCaller{
		responses: []string{
			`[{"title":"RCE","severity":"Critical","cwe":"CWE-94","endpoint":"/x","evidence":"uid=0"}]`,
			`[]`,
		},
	}
	engine := &Engine{
		Caller: caller,
		ParseFindings: func(text, agent string) []types.Finding {
			if strings.Contains(text, "RCE") {
				return []types.Finding{{Title: "RCE", Severity: "Critical"}}
			}
			return nil
		},
	}
	chains := []agents.Agent{
		{Name: "stage1", Title: "Stage 1"},
		{Name: "stage2", Title: "Stage 2"},
	}
	out := engine.Run(context.Background(), Config{
		Target:    "http://test",
		Confirmed: []types.Finding{{Title: "SQLi", CWE: "CWE-89"}},
		Chains:    chains,
	})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d (calls=%d)", len(out), caller.calls)
	}
	if caller.calls != 2 {
		t.Fatalf("expected 2 calls (second returns empty → stop), got %d", caller.calls)
	}
}
