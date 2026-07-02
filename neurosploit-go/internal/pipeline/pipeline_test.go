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
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
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

func (s stubPool) VoteDetailed(system, user string, n int, skip string) (int, int, []pool.VoteDetail) {
	yes, total := s.Vote(system, user, n, skip)
	return yes, total, nil
}

func (s stubPool) StopExploiting() bool { return false }

func (s stubPool) Tools() *tools.Registry   { return nil }
func (s stubPool) Executor() tools.Executor { return nil }
func (s stubPool) Skills() *skills.Library  { return nil }
func (s stubPool) CompleteWithTools(label string, task pool.Task, system, user string, tools []map[string]any) (models.ModelRef, string, error) {
	return s.Complete(label, task, system, user)
}

func TestSQLMapHarnessArgsValidate(t *testing.T) {
	root := findRepoRoot(t)
	reg, err := tools.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := reg.Get("sqlmap")
	if !ok {
		t.Fatal("sqlmap tool missing")
	}
	args := sqlmapHarnessArgs("http://example.com/Comments.aspx?id=1")
	res := tools.ValidateCall(tool, args, "http://example.com")
	if !res.Runnable {
		t.Fatalf("harness args not runnable: %+v", res.Issues)
	}
	cmd, err := tools.BuildCommand(tool, res.Args)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmd, " ")
	for _, flag := range []string{"--batch", "--flush-session", "--fresh-queries"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("command missing %s: %s", flag, joined)
		}
	}
}

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

func TestRunGreyboxOffline(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-gb")
	wd := workdir
	repo := "/tmp/nonexistent-repo"
	cfg := types.NewRunConfig("http://example.test")
	cfg.Repo = &repo
	cfg.Offline = true
	cfg.Workdir = &wd
	cfg.MaxAgents = 1
	progress := make(chan string, 8)
	go func() {
		for range progress {
		}
	}()
	out := RunGreybox(context.Background(), cfg, lib, stubPool{reconJSON: `{}`, exploitJSON: `[]`}, progress)
	if out.Workdir != workdir {
		t.Fatalf("workdir = %q", out.Workdir)
	}
}

func TestRunHostOffline(t *testing.T) {
	base := findRepoRoot(t)
	lib := agents.Load(base)
	workdir := filepath.Join(t.TempDir(), "runs", "ns-host")
	wd := workdir
	cfg := types.NewRunConfig("10.0.0.1")
	cfg.Offline = true
	cfg.Workdir = &wd
	cfg.MaxAgents = 1
	progress := make(chan string, 8)
	go func() {
		for range progress {
		}
	}()
	out := RunHost(context.Background(), cfg, lib, stubPool{reconJSON: `{}`, exploitJSON: `[]`}, progress)
	if out.Workdir != workdir {
		t.Fatalf("workdir = %q", out.Workdir)
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
