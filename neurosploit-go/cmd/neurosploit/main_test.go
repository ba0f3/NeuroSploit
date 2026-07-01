package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func execute(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	cmd.SetArgs(args)
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	os.Stderr = w
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()
	_, execErr := cmd.ExecuteC()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String(), execErr
}

func TestRootHelp(t *testing.T) {
	out, err := execute(t, rootCmd(), "--help")
	if err != nil {
		t.Fatalf("root help failed: %v", err)
	}
	if !strings.Contains(out, "Available Commands") {
		t.Errorf("help missing commands: %q", out)
	}
}

func TestModelsCmd(t *testing.T) {
	out, err := execute(t, rootCmd(), "models")
	if err != nil {
		t.Fatalf("models failed: %v", err)
	}
	if !strings.Contains(out, "anthropic") {
		t.Errorf("models output missing anthropic: %q", out)
	}
}

func TestAgentsCmd(t *testing.T) {
	base := findBase()
	if _, err := os.Stat(filepath.Join(base, "agents_md")); err != nil {
		t.Skip("agents_md not found")
	}
	out, err := execute(t, rootCmd(), "agents", "--base", base)
	if err != nil {
		t.Fatalf("agents failed: %v", err)
	}
	if !strings.Contains(out, "Total agents") {
		t.Errorf("agents output missing total: %q", out)
	}
}

func TestToolsCmd(t *testing.T) {
	base := findBase()
	if _, err := os.Stat(filepath.Join(base, "toolsdata")); err != nil {
		t.Skip("toolsdata not found")
	}
	out, _ := execute(t, rootCmd(), "tools", "--base", base, "--extras=false")
	if !strings.Contains(out, "Tool recipes") {
		t.Errorf("tools output missing header: %q", out)
	}
}

func TestOfflineRun(t *testing.T) {
	base := findBase()
	if _, err := os.Stat(filepath.Join(base, "agents_md")); err != nil {
		t.Skip("agents_md not found")
	}
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	out, err := execute(t, rootCmd(), "run", "http://example.com", "--offline", "--max-agents", "2", "-v")
	if err != nil {
		t.Fatalf("offline run failed: %v", err)
	}
	if !strings.Contains(out, "SQLi") && !strings.Contains(out, "workdir:") {
		t.Errorf("offline run output unexpected: %q", out)
	}
}

func TestVersion(t *testing.T) {
	cmd := rootCmd()
	cmd.SetVersionTemplate("{{.Version}}\n")
	out, err := execute(t, cmd, "--version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if strings.TrimSpace(out) != "dev" {
		t.Errorf("version = %q, want dev", out)
	}
}
