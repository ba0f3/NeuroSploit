package agents_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
)

// findRepoRoot walks up from start until it finds a directory containing agents_md/.
func findRepoRoot(start string) string {
	abs, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, "agents_md")); err == nil {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return ""
}

// countMDFiles counts *.md files at depth 1 inside dir.
func countMDFiles(dir string) int {
	if _, err := os.Stat(dir); err != nil {
		return 0
	}
	count := 0
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			count++
		}
		return nil
	}); err != nil {
		return 0
	}
	return count
}

func TestLoadLibrary(t *testing.T) {
	root := findRepoRoot(".")
	if root == "" {
		wd, _ := os.Getwd()
		t.Fatalf("could not find repo root containing agents_md from %s", wd)
	}

	lib := agents.Load(root)

	if lib.Total() <= 0 {
		t.Fatalf("expected library to be non-empty, got Total() == %d", lib.Total())
	}

	var sqli *agents.Agent
	for _, a := range lib.Vulns {
		if a.Name == "sqli_error" {
			sqli = &a
			break
		}
	}
	if sqli == nil {
		t.Fatalf("expected Vulns to contain sqli_error")
	}
	if sqli.CWE != "CWE-89" {
		t.Errorf("sqli_error CWE: want CWE-89, got %s", sqli.CWE)
	}
	if !strings.Contains(strings.ToLower(sqli.Title), "sql") {
		t.Errorf("sqli_error Title: want substring 'SQL', got %s", sqli.Title)
	}
	if strings.TrimSpace(sqli.System) == "" {
		t.Errorf("sqli_error System prompt should be non-empty")
	}
	if strings.TrimSpace(sqli.User) == "" {
		t.Errorf("sqli_error User prompt should be non-empty")
	}

	wantCount := 0
	for _, subdir := range []string{"vulns", "meta", "recon", "code", "infra", "chains"} {
		wantCount += countMDFiles(filepath.Join(root, "agents_md", subdir))
	}
	if got := lib.Total(); got != wantCount {
		t.Errorf("Total() = %d, want %d", got, wantCount)
	}
}

func TestParseAgentMetadata(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "agents_md", "vulns"), 0755)
	content := `# Test Agent

## System Prompt
You are a test agent.

## Tools
- nmap
- nuclei
- curl

## Skills
- web_recon
- cve_scanning

## Output Schema
{ "title": "string", "severity": "string" }

## Preconditions
- Must have a URL
- Must have a valid session

## User Prompt
Run tests.
`
	_ = os.WriteFile(filepath.Join(dir, "agents_md", "vulns", "test_agent.md"), []byte(content), 0644)
	lib := agents.Load(dir)
	if len(lib.Vulns) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(lib.Vulns))
	}
	a := lib.Vulns[0]
	if len(a.Tools) != 3 || a.Tools[0] != "nmap" {
		t.Fatalf("tools = %v", a.Tools)
	}
	if len(a.Skills) != 2 || a.Skills[0] != "web_recon" {
		t.Fatalf("skills = %v", a.Skills)
	}
	if a.OutputSchema == "" {
		t.Fatal("expected output schema")
	}
	if len(a.Preconditions) != 2 {
		t.Fatalf("preconditions = %v", a.Preconditions)
	}
}
