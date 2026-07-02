package chainengine

import (
	"context"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

type mockSeedCaller struct {
	responses []struct {
		findings []types.Finding
		loot     []string
	}
	calls int
	stop  bool
}

func (m *mockSeedCaller) StopExploiting() bool { return m.stop }

func (m *mockSeedCaller) ChainFromSeed(ctx context.Context, seed types.Finding, loot []string, round, maxRounds int, recipeBlock string) ([]types.Finding, []string, error) {
	if m.calls >= len(m.responses) {
		return nil, nil, nil
	}
	r := m.responses[m.calls]
	m.calls++
	return r.findings, r.loot, nil
}

func TestEngineStopsOnEmptyRound(t *testing.T) {
	caller := &mockSeedCaller{
		responses: []struct {
			findings []types.Finding
			loot     []string
		}{
			{findings: []types.Finding{{Title: "RCE", Severity: "Critical", CWE: "CWE-94"}}},
		},
	}
	validated := 0
	engine := &Engine{Caller: caller}
	out := engine.Run(context.Background(), Config{
		ChainDepth: 2,
		Confirmed:  []types.Finding{{Title: "SQLi", Severity: "High", CWE: "CWE-89"}},
		Validate: func(candidates []types.Finding) []types.Finding {
			validated += len(candidates)
			return candidates
		},
		FindingKey: func(f types.Finding) string { return f.Title },
		ExtractChain: func(text, agent string) ([]types.Finding, []string) {
			return nil, nil
		},
	})
	if len(out) != 1 {
		t.Fatalf("expected 1 validated finding, got %d", len(out))
	}
	if caller.calls != 1 {
		t.Fatalf("expected 1 seed call (round 2 dry), got %d", caller.calls)
	}
}

func TestEngineCarriesLootAcrossRounds(t *testing.T) {
	caller := &mockSeedCaller{
		responses: []struct {
			findings []types.Finding
			loot     []string
		}{
			{findings: []types.Finding{{Title: "Stage1", Severity: "High"}}},
			{findings: []types.Finding{{Title: "Stage2", Severity: "Critical"}}},
		},
	}
	engine := &Engine{Caller: caller}
	out := engine.Run(context.Background(), Config{
		ChainDepth: 2,
		Confirmed:  []types.Finding{{Title: "SQLi", Severity: "High"}},
		Validate: func(candidates []types.Finding) []types.Finding {
			return candidates
		},
		FindingKey: func(f types.Finding) string { return f.Title },
		ExtractChain: func(text, agent string) ([]types.Finding, []string) {
			return nil, nil
		},
	})
	if len(out) != 2 {
		t.Fatalf("expected 2 chain findings, got %d", len(out))
	}
	if caller.calls != 2 {
		t.Fatalf("expected 2 seed calls, got %d", caller.calls)
	}
}

func TestEngineZeroDepth(t *testing.T) {
	engine := &Engine{Caller: &mockSeedCaller{}}
	out := engine.Run(context.Background(), Config{
		ChainDepth: 0,
		Confirmed:  []types.Finding{{Title: "X"}},
		Validate:   func([]types.Finding) []types.Finding { return nil },
		FindingKey: func(f types.Finding) string { return f.Title },
	})
	if out != nil {
		t.Fatalf("expected nil for depth 0, got %v", out)
	}
}

func TestRecipeBlock(t *testing.T) {
	block := recipeBlock([]agents.Agent{{Title: "SQLi Agent"}})
	if block == "" || !contains(block, "SQLi") {
		t.Fatalf("unexpected recipe block: %q", block)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
