package toolloop

import (
	"context"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
)

// PoolAdapter adapts a pool.ModelPool to the toolloop Caller interface.
// It routes each prompt to the best model for the task and returns the raw
// response (which may contain native tool_calls or plain text tags).
type PoolAdapter struct {
	Pool  *pool.ModelPool
	Task  pool.Task
	Label string
}

// Call implements the Caller interface.
func (a *PoolAdapter) Call(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error) {
	_, text, err := a.Pool.CompleteWithTools(a.Label, a.Task, system, user, toolsJSON)
	return text, err
}

// NewPoolAdapter creates a Caller backed by a model pool.
func NewPoolAdapter(p *pool.ModelPool, task pool.Task, label string) Caller {
	return &PoolAdapter{Pool: p, Task: task, Label: label}
}

var _ Caller = (*PoolAdapter)(nil)
