package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/registry"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

type fakeRunnerClient struct{}

func (fakeRunnerClient) Chat(ctx context.Context, m models.ModelRef, system, user string) (string, error) {
	if contains(system, "security tester") {
		return "HTTP/1.1 200 OK\nContent-Type: text/html\n\nfinding: XSS CWE-79 on /search", nil
	}
	return "target appears to be a web app", nil
}

func (fakeRunnerClient) ChatCLI(ctx context.Context, label, provider, model, system, user, mcpConfig string, progress chan<- string) (string, error) {
	return fakeRunnerClient{}.Chat(ctx, models.ModelRef{Provider: provider, Model: model}, system, user)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || find(s, sub))
}

func find(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestNewRunner(t *testing.T) {
	p := pool.New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	p.Client = fakeRunnerClient{}
	r := New(p, nil, nil, nil)
	if r == nil || r.World == nil {
		t.Fatal("New returned nil runner or world")
	}
}

func TestRunLoop(t *testing.T) {
	p := pool.New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	p.Client = fakeRunnerClient{}
	reg := registry.New(filepath.Join(t.TempDir(), "findings.jsonl"))
	wm := &belief.WorldModel{Nodes: map[string]belief.Node{}}
	wm.Add("xss", belief.KindVuln, "reflected xss", 0.95)
	r := New(p, reg, wm, nil)
	cfg := types.NewRunConfig("http://example.com")
	cfg.MaxAgents = 3
	if err := r.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(r.Findings()) == 0 {
		t.Errorf("expected at least one finding")
	}
}

func TestValidate(t *testing.T) {
	p := pool.New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
		models.ModelRefParse("openai:gpt-5.5"),
		models.ModelRefParse("xai:grok-4"),
	}, 3)
	p.Client = &yesClient{}
	f := types.Finding{Agent: "anthropic:claude-opus-4-8", Title: "XSS", CWE: "CWE-79"}
	r := New(p, nil, nil, nil)
	confirmed, err := r.Validate(context.Background(), f)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if !confirmed {
		t.Errorf("expected confirmed finding")
	}
}

type yesClient struct{}

func (yesClient) Chat(ctx context.Context, m models.ModelRef, system, user string) (string, error) {
	return "yes", nil
}

func (yesClient) ChatCLI(ctx context.Context, label, provider, model, system, user, mcpConfig string, progress chan<- string) (string, error) {
	return "yes", nil
}
