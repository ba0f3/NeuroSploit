package pipeline

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestRunWhiteboxOffline(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-wb")
	wd := workdir
	cfg := types.NewRunConfig("/tmp/nonexistent-repo")
	cfg.Offline = true
	cfg.Workdir = &wd
	cfg.MaxAgents = 1
	progress := make(chan string, 8)
	go func() {
		for range progress {
		}
	}()
	out := RunWhitebox(context.Background(), cfg, lib, stubPool{reconJSON: `{}`, exploitJSON: `[]`}, progress)
	if out.Workdir != workdir {
		t.Fatalf("workdir = %q", out.Workdir)
	}
}
