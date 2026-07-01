package playbooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

type mockExecutor struct {
	results map[string]tools.ToolResult
}

func (m *mockExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	if r, ok := m.results[call.Name]; ok {
		r.Name = call.Name
		return r, nil
	}
	return tools.ToolResult{IsError: true, Error: "not found"}, nil
}

func nmapTool() tools.Tool {
	return tools.Tool{
		Name:    "nmap",
		Command: "nmap",
		Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, Format: "positional", Position: 0},
		},
	}
}

func TestLoadPlaybooks(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "playbooks"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "playbooks", "demo.yaml"), []byte(`
name: Demo
description: Demo playbook.
variables:
  - name: target
    type: string
    required: true
phases:
  - name: scan
    tools: [nmap]
`), 0644)

	r, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pb, ok := r.Get("Demo")
	if !ok {
		t.Fatal("expected Demo playbook")
	}
	if len(pb.Phases) != 1 {
		t.Fatalf("phases = %d", len(pb.Phases))
	}
}

func TestEngineRunsToolsAndAgents(t *testing.T) {
	reg := &tools.Registry{}
	reg.RegisterTool(nmapTool())
	exec := &mockExecutor{
		results: map[string]tools.ToolResult{
			"nmap": {Output: "80/tcp open http"},
		},
	}
	eng := &Engine{
		ToolRegistry: reg,
		Executor:     exec,
		AgentRunner: func(ctx context.Context, name string, state map[string]any) ([]types.Finding, error) {
			if name == "xss_reflected" {
				return []types.Finding{{Title: "XSS", Severity: "High", CWE: "CWE-79"}}, nil
			}
			return nil, nil
		},
	}
	pb := Playbook{
		Name:      "Test",
		Variables: []Variable{{Name: "target", Type: "string", Required: true}},
		Phases: []Phase{
			{Name: "recon", Tools: []string{"nmap"}, Agents: []string{"xss_reflected"}},
		},
	}
	state, findings, err := eng.Run(context.Background(), pb, map[string]string{"target": "example.com"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if state["target"] != "example.com" {
		t.Fatalf("state target = %v", state["target"])
	}
	if _, ok := state["tool_nmap"]; !ok {
		t.Fatal("expected tool_nmap in state")
	}
}

func TestEngineCondition(t *testing.T) {
	reg := &tools.Registry{}
	reg.RegisterTool(nmapTool())
	exec := &mockExecutor{results: map[string]tools.ToolResult{}}
	eng := &Engine{ToolRegistry: reg, Executor: exec}
	pb := Playbook{
		Variables: []Variable{{Name: "target", Type: "string", Required: true}},
		Phases: []Phase{
			{Name: "skip", Condition: "should_run", Tools: []string{"nmap"}},
			{Name: "run", Condition: "", Tools: []string{"nmap"}},
		},
	}
	state, _, err := eng.Run(context.Background(), pb, map[string]string{"target": "x"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := state["tool_nmap"]; !ok {
		t.Fatal("expected tool_nmap in state")
	}
	if _, ok := state["phase_skip_done"]; ok {
		t.Fatal("phase skip should not have run")
	}
}

func TestEngineNumericCondition(t *testing.T) {
	eng := &Engine{}
	if !eng.evalCondition("findings_count > 0", map[string]any{"findings_count": 3}) {
		t.Fatal("expected findings_count > 0 to be true")
	}
	if eng.evalCondition("findings_count > 0", map[string]any{"findings_count": 0}) {
		t.Fatal("expected findings_count > 0 to be false when 0")
	}
}

func TestLoadRealPlaybooks(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	r, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.List()) < 1 {
		t.Fatalf("expected at least 1 playbook, got %d", len(r.List()))
	}
}

func TestSkillInjection(t *testing.T) {
	reg := &tools.Registry{}
	exec := &mockExecutor{results: map[string]tools.ToolResult{}}
	lib, _ := skills.Load(t.TempDir())
	eng := &Engine{ToolRegistry: reg, Executor: exec, SkillLibrary: lib}
	pb := Playbook{
		Variables: []Variable{{Name: "target", Type: "string", Required: true}},
		Phases:    []Phase{{Name: "recon", Skills: []string{"web_recon"}}},
	}
	_, _, err := eng.Run(context.Background(), pb, map[string]string{"target": "x"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "agents_md")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "toolsdata")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
