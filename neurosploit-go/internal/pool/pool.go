package pool

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
)

// Task describes the kind of work the model router should optimize for.
type Task int

const (
	TaskRecon Task = iota
	TaskSelect
	TaskExploit
	TaskValidate
	TaskDefault
)

// ChatClient is the subset of models.ChatClient used by the pool (testable interface).
type ChatClient interface {
	Chat(ctx context.Context, m models.ModelRef, system, user string) (string, error)
	ChatCLI(ctx context.Context, label, provider, model, system, user, mcpConfig string, progress chan<- string) (string, error)
}

// ModelPool routes prompts across a panel of models with failover and concurrency limits.
type ModelPool struct {
	Client       ChatClient
	Sem          chan struct{}
	Candidates   []models.ModelRef
	Subscription bool
	MCPConfig    string
	Progress     chan<- string

	cancel  atomic.Bool
	soft    atomic.Bool
	paused  atomic.Bool
	resume  chan struct{}
	mu      sync.Mutex
	fallback []models.ModelRef
}

// IsExhaustion reports whether an error looks like token/quota/rate-limit exhaustion.
func IsExhaustion(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	markers := []string{
		"rate limit", "rate_limit", "ratelimit", "429", "too many requests",
		"quota", "insufficient_quota", "insufficient quota", "out of credit",
		"credit balance", "billing", "exhausted", "overloaded", "capacity",
		"usage limit", "resource_exhausted", "resource exhausted",
	}
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func isFast(model string) bool {
	m := strings.ToLower(model)
	for _, k := range []string{"haiku", "flash", "fast", "mini", "lite", "chat", "small"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

// New creates a model pool with the given candidates and concurrency cap.
func New(candidates []models.ModelRef, concurrency int) *ModelPool {
	return WithAuth(candidates, concurrency, false, "")
}

// WithAuth creates a model pool with optional subscription-CLI routing and MCP config.
func WithAuth(candidates []models.ModelRef, concurrency int, subscription bool, mcpConfig string) *ModelPool {
	if concurrency < 1 {
		concurrency = 1
	}
	if subscription && concurrency > 3 {
		concurrency = 3
	}
	return &ModelPool{
		Candidates:   candidates,
		Subscription: subscription,
		MCPConfig:    mcpConfig,
		Sem:          make(chan struct{}, concurrency),
		resume:       make(chan struct{}),
	}
}

// Cancel hard-stops in-flight calls.
func (p *ModelPool) Cancel() { p.cancel.Store(true) }

// IsCancelled reports whether the pool is hard-cancelled.
func (p *ModelPool) IsCancelled() bool { return p.cancel.Load() }

// Stop soft-stops launching new exploit agents.
func (p *ModelPool) Stop() { p.soft.Store(true) }

// IsStopped reports whether the pool is soft-stopped.
func (p *ModelPool) IsStopped() bool { return p.soft.Load() }

// Pause sets the exhausted flag so callers can wait for /continue.
func (p *ModelPool) Pause() { p.paused.Store(true) }

// Continue resumes a paused pool and optionally adds a fallback model.
func (p *ModelPool) Continue(additional string) {
	p.mu.Lock()
	if additional != "" {
		p.fallback = append([]models.ModelRef{models.ModelRefParse(additional)}, p.fallback...)
	}
	p.mu.Unlock()
	p.paused.Store(false)
	select {
	case p.resume <- struct{}{}:
	default:
	}
}

// WaitPaused blocks until the pool is resumed.
func (p *ModelPool) WaitPaused() {
	if !p.paused.Load() {
		return
	}
	<-p.resume
}

// One calls a single model (API or CLI subscription) and returns its output.
func (p *ModelPool) One(label string, m models.ModelRef, system, user string) (string, error) {
	if p.cancel.Load() {
		return "", fmt.Errorf("cancelled")
	}
	if p.Client == nil {
		return "", fmt.Errorf("no chat client configured")
	}
	select {
	case p.Sem <- struct{}{}:
		defer func() { <-p.Sem }()
	case <-time.After(30 * time.Second):
		return "", fmt.Errorf("could not acquire pool semaphore")
	}
	if p.cancel.Load() {
		return "", fmt.Errorf("cancelled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if p.Subscription {
		return p.Client.ChatCLI(ctx, label, m.Provider, m.Model, system, user, p.MCPConfig, p.Progress)
	}
	return p.Client.Chat(ctx, m, system, user)
}

// Complete routes a prompt to the best model for task, failing over on exhaustion.
func (p *ModelPool) Complete(label string, task Task, system, user string) (models.ModelRef, string, error) {
	for {
		if p.cancel.Load() {
			return models.ModelRef{}, "", fmt.Errorf("cancelled")
		}
		order := p.Route(task)
		var exhausted bool
		var lastErr error
		for _, m := range order {
			if p.cancel.Load() {
				return models.ModelRef{}, "", fmt.Errorf("cancelled")
			}
			if task == TaskExploit && p.soft.Load() {
				return models.ModelRef{}, "", fmt.Errorf("soft-stopped")
			}
			text, err := p.ONE(label, m, system, user)
			if err == nil {
				return m, text, nil
			}
			if IsExhaustion(err) {
				exhausted = true
			}
			lastErr = err
		}
		if exhausted && !p.cancel.Load() {
			p.Pause()
			p.WaitPaused()
			continue
		}
		return models.ModelRef{}, "", lastErr
	}
}

// ONE is an alias for One to satisfy the plan interface naming.
func (p *ModelPool) ONE(label string, m models.ModelRef, system, user string) (string, error) {
	return p.One(label, m, system, user)
}

// Route returns candidates reordered for the task.
func (p *ModelPool) Route(task Task) []models.ModelRef {
	p.mu.Lock()
	fallback := make([]models.ModelRef, len(p.fallback))
	copy(fallback, p.fallback)
	p.mu.Unlock()
	order := make([]models.ModelRef, 0, len(fallback)+len(p.Candidates))
	order = append(order, fallback...)
	order = append(order, p.Candidates...)
	if len(order) < 2 {
		return order
	}
	switch task {
	case TaskRecon, TaskSelect:
		for i := range order {
			for j := i + 1; j < len(order); j++ {
				if isFast(order[i].Model) == isFast(order[j].Model) {
					continue
				}
				if !isFast(order[i].Model) && isFast(order[j].Model) {
					order[i], order[j] = order[j], order[i]
				}
			}
		}
	case TaskExploit, TaskDefault:
		// panel order (primary first)
	case TaskValidate:
		// handled by Vote rotation
	}
	return order
}

// Vote asks up to n distinct models the same yes/no validation question.
func (p *ModelPool) Vote(system, user string, n int, skip string) (int, int) {
	ordered := make([]models.ModelRef, len(p.Candidates))
	copy(ordered, p.Candidates)
	if len(ordered) > 1 && skip != "" {
		for i := range ordered {
			if ordered[i].Label() == skip {
				found := ordered[i]
				ordered = append(append([]models.ModelRef{}, ordered[:i]...), ordered[i+1:]...)
				ordered = append(ordered, found)
				break
			}
		}
	}
	if n < 1 {
		n = 1
	}
	if n > len(ordered) {
		n = len(ordered)
	}
	panel := ordered[:n]
	confirmed, total := 0, 0
	for _, m := range panel {
		select {
		case p.Sem <- struct{}{}:
			if text, err := p.ONE("validate", m, system, user); err == nil {
				total++
				t := strings.ToLower(text)
				if strings.Contains(t, `"verdict": "confirmed"`) ||
					strings.HasPrefix(strings.TrimSpace(t), "yes") ||
					strings.Contains(t, "confirmed: true") ||
					strings.Contains(t, `is_real": true`) {
					confirmed++
				}
			}
			<-p.Sem
		default:
			break
		}
	}
	return confirmed, total
}

