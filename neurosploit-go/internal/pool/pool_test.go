package pool

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
)

type fakeClient struct {
	fail    bool
	exhaust bool
}

func (f fakeClient) Chat(ctx context.Context, m models.ModelRef, system, user string) (string, error) {
	if f.fail {
		if f.exhaust {
			return "", errors.New("rate limit exceeded")
		}
		return "", errors.New("generic failure")
	}
	return "yes", nil
}

func (f fakeClient) ChatCLI(ctx context.Context, label, provider, model, system, user, mcpConfig string, progress chan<- string) (string, error) {
	return f.Chat(ctx, models.ModelRef{Provider: provider, Model: model}, system, user)
}

func TestSetProgress(t *testing.T) {
	p := New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	ch := make(chan string, 1)
	p.SetProgress(ch)
	if p.Progress == nil {
		t.Fatal("Progress not set")
	}
}

func TestStopExploiting(t *testing.T) {
	p := New([]models.ModelRef{models.ModelRefParse("anthropic:claude-opus-4-8")}, 1)
	if p.StopExploiting() {
		t.Fatal("expected false before stop")
	}
	p.Stop()
	if !p.StopExploiting() {
		t.Fatal("expected true after Stop")
	}
}

func TestIsExhaustion(t *testing.T) {
	if !IsExhaustion(errors.New("rate limit exceeded")) {
		t.Error("expected rate limit to be exhaustion")
	}
	if IsExhaustion(errors.New("network timeout")) {
		t.Error("network timeout is not exhaustion")
	}
}

func TestRouteFastFirst(t *testing.T) {
	pool := New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
		models.ModelRefParse("anthropic:claude-haiku-4-5"),
	}, 2)
	order := pool.Route(TaskRecon)
	if order[0].Model != "claude-haiku-4-5" {
		t.Errorf("expected fast model first, got %v", order)
	}
}

func TestCompleteSuccess(t *testing.T) {
	pool := New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
	}, 1)
	pool.Client = fakeClient{}
	m, text, err := pool.Complete("test", TaskDefault, "sys", "user")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if !strings.Contains(text, "yes") {
		t.Errorf("unexpected text: %q", text)
	}
	if m.Provider != "anthropic" {
		t.Errorf("unexpected model: %+v", m)
	}
}

func TestVoteSkip(t *testing.T) {
	pool := New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
		models.ModelRefParse("openai:gpt-5.5"),
	}, 2)
	pool.Client = fakeClient{}
	confirmed, total := pool.Vote("sys", "user", 2, "anthropic:claude-opus-4-8")
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if confirmed != 2 {
		t.Errorf("confirmed = %d, want 2", confirmed)
	}
}

func TestCancel(t *testing.T) {
	pool := New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
	}, 1)
	pool.Client = fakeClient{fail: true}
	pool.Cancel()
	_, _, err := pool.Complete("test", TaskDefault, "sys", "user")
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("expected cancelled error, got %v", err)
	}
}

func TestContinueAddsFallback(t *testing.T) {
	pool := New([]models.ModelRef{
		models.ModelRefParse("anthropic:claude-opus-4-8"),
	}, 1)
	pool.Continue("openai:gpt-5.5")
	order := pool.Route(TaskDefault)
	if len(order) < 2 || order[0].Label() != "openai:gpt-5.5" {
		t.Errorf("fallback not first in route: %v", order)
	}
}
