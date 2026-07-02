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

const sampleSQLMapOut = `---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[14:10:23] [INFO] testing 'Microsoft SQL Server'
[14:10:45] [INFO] the back-end DBMS is Microsoft SQL Server
`

func TestExtractSQLMapProof(t *testing.T) {
	proof := extractSQLMapProof(sampleSQLMapOut)
	if !strings.Contains(proof, "Parameter: id") {
		t.Fatalf("missing parameter block: %q", proof)
	}
	if !strings.Contains(strings.ToLower(proof), "payload:") {
		t.Fatalf("missing payload: %q", proof)
	}
}

func TestBuildSQLMapEvidenceIncludesLogPath(t *testing.T) {
	ev := buildSQLMapEvidence(sampleSQLMapOut, "/tmp/sqlmap.log")
	if !strings.Contains(ev, "Parameter: id") {
		t.Fatalf("missing proof: %q", ev)
	}
	if !strings.Contains(ev, "Full log: /tmp/sqlmap.log") {
		t.Fatalf("missing log path: %q", ev)
	}
}

func TestSQLMapProofVerified(t *testing.T) {
	ev := buildSQLMapEvidence(sampleSQLMapOut, "/tmp/sqlmap.log")
	if !sqlmapProofVerified(ev) {
		t.Fatal("expected tool-verified evidence")
	}
	if sqlmapProofVerified("curl only output") {
		t.Fatal("curl-only should not verify")
	}
}

func TestParseSQLMapFindingTitle(t *testing.T) {
	f := parseSQLMapFinding(sampleSQLMapOut, "http://example.com/Comments.aspx?id=1", "sqli_blind", "/tmp/log")
	if f == nil {
		t.Fatal("expected finding")
	}
	if !strings.Contains(f.Title, "id") {
		t.Fatalf("title should include param: %q", f.Title)
	}
	if f.Severity != "Critical" {
		t.Fatalf("severity=%q", f.Severity)
	}
	if !strings.Contains(f.Evidence, "Full log:") {
		t.Fatalf("evidence=%q", f.Evidence)
	}
}

func TestSQLiPreflightSkipLoop(t *testing.T) {
	executor := &stubSQLMapExecutor{out: sampleSQLMapOut, logPath: "/tmp/sqlmap.log"}
	reg := toolsRegistryWithSQLMap()
	p := preflightStubPool{executor: executor, reg: reg}
	recon := `{"endpoints":["http://example.com/Comments.aspx"],"params":[{"endpoint":"http://example.com/Comments.aspx","params":["id"]}]}`
	ag := agents.Agent{Name: "sqli_blind"}
	findings, _, skip := sqliPreflight(context.Background(), p, ag, recon, "http://example.com", nil)
	if !skip {
		t.Fatal("expected skipLoop when injectable")
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestDedupKeepsLongerEvidence(t *testing.T) {
	in := []types.Finding{
		{Title: "SQLi", CWE: "CWE-89", Endpoint: "/x", Confidence: 0.85, Evidence: "short"},
		{Title: "SQLi", CWE: "CWE-89", Endpoint: "/x", Confidence: 0.7, Evidence: strings.Repeat("x", 200)},
	}
	got := dedupFindings(in)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if len(got[0].Evidence) < 100 {
		t.Fatalf("kept shorter evidence: len=%d", len(got[0].Evidence))
	}
}

func TestValidateWritesVotes(t *testing.T) {
	dir := t.TempDir()
	p := voteDetailStubPool{}
	candidates := []types.Finding{{
		Title:    "SQL Injection",
		Severity: "Critical",
		CWE:      "CWE-89",
		Endpoint: "http://example.com/x",
		Evidence: buildSQLMapEvidence(sampleSQLMapOut, "/tmp/sqlmap.log"),
	}}
	_, records := validate(candidates, p, voteSys, 2, nil)
	if len(records) != 2 {
		t.Fatalf("expected 2 vote records, got %d", len(records))
	}
	path := persistVotes(dir, records)
	if path == "" {
		t.Fatal("persistVotes returned empty path")
	}
	if _, err := os.Stat(filepath.Join(dir, "votes.json")); err != nil {
		t.Fatalf("votes.json missing: %v", err)
	}
}

type stubSQLMapExecutor struct {
	out     string
	logPath string
}

func (s *stubSQLMapExecutor) Execute(_ context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	return tools.ToolResult{Name: call.Name, ID: call.ID, Output: s.out, LogPath: s.logPath}, nil
}

func toolsRegistryWithSQLMap() *tools.Registry {
	r := &tools.Registry{}
	r.RegisterTool(tools.Tool{Name: "sqlmap"})
	return r
}

type preflightStubPool struct {
	executor tools.Executor
	reg      *tools.Registry
}

func (p preflightStubPool) SetProgress(chan<- string) {}
func (p preflightStubPool) Complete(string, pool.Task, string, string) (models.ModelRef, string, error) {
	panic("unused")
}
func (p preflightStubPool) CompleteWithTools(string, pool.Task, string, string, []map[string]any) (models.ModelRef, string, error) {
	panic("unused")
}
func (p preflightStubPool) Vote(string, string, int, string) (int, int) { return 0, 0 }
func (p preflightStubPool) VoteDetailed(string, string, int, string) (int, int, []pool.VoteDetail) {
	return 0, 0, nil
}
func (p preflightStubPool) StopExploiting() bool              { return false }
func (p preflightStubPool) Tools() *tools.Registry            { return p.reg }
func (p preflightStubPool) Executor() tools.Executor          { return p.executor }
func (p preflightStubPool) Skills() *skills.Library           { return nil }

type voteDetailStubPool struct{}

func (voteDetailStubPool) SetProgress(chan<- string) {}
func (voteDetailStubPool) Complete(string, pool.Task, string, string) (models.ModelRef, string, error) {
	panic("unused")
}
func (voteDetailStubPool) CompleteWithTools(string, pool.Task, string, string, []map[string]any) (models.ModelRef, string, error) {
	panic("unused")
}
func (voteDetailStubPool) Vote(string, string, int, string) (int, int) { return 1, 2 }
func (voteDetailStubPool) VoteDetailed(string, string, int, string) (int, int, []pool.VoteDetail) {
	return 1, 2, []pool.VoteDetail{
		{Model: "model-a", Verdict: "confirmed", Reason: "proof ok"},
		{Model: "model-b", Verdict: "rejected", Reason: "truncated"},
	}
}
func (voteDetailStubPool) StopExploiting() bool     { return false }
func (voteDetailStubPool) Tools() *tools.Registry   { return nil }
func (voteDetailStubPool) Executor() tools.Executor { return nil }
func (voteDetailStubPool) Skills() *skills.Library  { return nil }
