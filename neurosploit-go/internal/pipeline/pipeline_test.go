package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

type stubPool struct {
	reconJSON   string
	exploitJSON string
}

func (s stubPool) SetProgress(chan<- string) {}

func (s stubPool) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	ref := models.ModelRef{Provider: "offline", Model: "stub"}
	switch task {
	case pool.TaskRecon:
		return ref, s.reconJSON, nil
	case pool.TaskSelect:
		return ref, `["sqli_error"]`, nil
	case pool.TaskExploit:
		return ref, s.exploitJSON, nil
	default:
		return ref, "{}", nil
	}
}

func (s stubPool) Vote(system, user string, n int, skip string) (int, int) { return n, n }

func (s stubPool) StopExploiting() bool { return false }

func findRepoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, "agents_md")); err == nil {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			t.Fatal("agents_md not found")
		}
		abs = parent
	}
}

func TestRunOfflineIntegration(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-test")
	wd := workdir
	rlPath := filepath.Join(t.TempDir(), "rl_state_go.json")
	cfg := types.NewRunConfig("http://example.test")
	cfg.Offline = false
	cfg.Workdir = &wd
	cfg.RLPath = &rlPath
	cfg.MaxAgents = 1
	cfg.VoteN = 1

	stub := stubPool{
		reconJSON:   `{}`,
		exploitJSON: `[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200 OK Server: nginx","payload":"'","confidence":0.9}]`,
	}
	progress := make(chan string, 64)
	go func() {
		for range progress {
		}
	}()

	out := Run(context.Background(), cfg, lib, stub, progress)
	if len(out.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if out.Findings[0].Title != "SQLi" {
		t.Fatalf("got %+v", out.Findings[0])
	}
	data, err := os.ReadFile(filepath.Join(workdir, "findings.json"))
	if err != nil {
		t.Fatalf("findings.json: %v", err)
	}
	if !strings.Contains(string(data), "SQLi") {
		t.Fatalf("findings.json content: %s", data)
	}
}
