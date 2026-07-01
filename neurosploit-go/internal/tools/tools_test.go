package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadTools(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "toolsdata"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "toolsdata", "curl.yaml"), []byte(`
name: curl
command: curl
args: ["-s", "-L"]
enabled: true
short_description: Fetch a URL with curl.
description: HTTP GET with optional headers and method.
parameters:
  - name: url
    type: string
    description: Target URL.
    required: true
    position: 0
    format: positional
  - name: method
    type: string
    description: HTTP method.
    required: false
    default: GET
    flag: -X
    format: flag
  - name: additional_args
    type: string
    description: Extra curl args.
    required: false
    format: positional
timeout: 30s
install_hint: apt install curl
tags: [http, recon]
`), 0644)

	r, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tool, ok := r.Get("curl")
	if !ok {
		t.Fatal("expected curl tool")
	}
	if tool.Command != "curl" {
		t.Fatalf("command = %q", tool.Command)
	}
	if tool.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v", tool.Timeout)
	}
	if len(tool.FunctionDefinition()["function"].(map[string]any)["parameters"].(map[string]any)["properties"].(map[string]any)) != 2 {
		t.Fatalf("unexpected schema properties: %v", tool.FunctionDefinition())
	}
}

func TestBuildCommand(t *testing.T) {
	tool := Tool{
		Name:    "nmap",
		Command: "nmap",
		Args:    []string{"-sV"},
		Parameters: []Parameter{
			{Name: "target", Required: true, Position: 0, Format: "positional"},
			{Name: "ports", Required: false, Flag: "-p", Format: "combined"},
			{Name: "additional_args", Format: "positional"},
		},
	}
	argv, err := BuildCommand(tool, map[string]any{"target": "example.com", "ports": "80,443"})
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	want := "nmap -sV example.com -p80,443"
	if strings.Join(argv, " ") != want {
		t.Fatalf("got %q want %q", strings.Join(argv, " "), want)
	}
}

func TestBuildCommandRequiredMissing(t *testing.T) {
	tool := Tool{
		Name:    "nmap",
		Command: "nmap",
		Parameters: []Parameter{
			{Name: "target", Required: true, Position: 0, Format: "positional"},
		},
	}
	if _, err := BuildCommand(tool, map[string]any{}); err == nil {
		t.Fatal("expected error for missing required parameter")
	}
}

func TestBuildCommandHttpxKali(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	r, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := r.Get("httpx")
	if !ok {
		t.Fatal("httpx not loaded")
	}
	argv, err := BuildCommand(tool, map[string]any{"target": "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	if strings.Contains(got, "-u ") {
		t.Fatalf("httpx must not use -u on Kali python httpx, got %q", got)
	}
	if !strings.Contains(got, "https://example.com") {
		t.Fatalf("missing target URL in %q", got)
	}
}

func TestBuildCommandNmapFromRecipe(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	r, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := r.Get("nmap")
	if !ok {
		t.Fatal("nmap not loaded")
	}
	argv, err := BuildCommand(tool, map[string]any{"target": "example.com", "ports": "80,443"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	want := "nmap -sV -sC -Pn example.com -p80,443"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMissingBinary(t *testing.T) {
	e := &DefaultExecutor{Registry: &Registry{tools: map[string]Tool{
		"missing": {Name: "missing", Command: "this-binary-does-not-exist-12345", Timeout: 10 * time.Second, InstallHint: "install it"},
	}}}
	res, _ := e.Execute(context.Background(), ToolCall{Name: "missing", Args: map[string]any{}})
	if !res.IsError || !strings.Contains(res.Error, "not found in PATH") {
		t.Fatalf("expected PATH error, got %+v", res)
	}
}

func TestDangerousCommandRejected(t *testing.T) {
	e := &DefaultExecutor{Registry: &Registry{tools: map[string]Tool{
		"bad": {Name: "bad", Command: "rm", Args: []string{"-rf", "/"}, Timeout: 10 * time.Second},
	}}}
	res, _ := e.Execute(context.Background(), ToolCall{Name: "bad", Args: map[string]any{}})
	if !res.IsError || !strings.Contains(res.Error, "dangerous") {
		t.Fatalf("expected dangerous rejection, got %+v", res)
	}
}

func TestRegistryWithout(t *testing.T) {
	r := &Registry{tools: map[string]Tool{
		"nmap": {Name: "nmap", Command: "nmap"},
		"curl": {Name: "curl", Command: "curl"},
	}}
	filtered := r.Without([]string{"nmap"})
	if _, ok := filtered.Get("nmap"); ok {
		t.Fatal("nmap should be removed")
	}
	if _, ok := filtered.Get("curl"); !ok {
		t.Fatal("curl should remain")
	}
}

func TestLoadRealTools(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	r, err := Load(root)
	if err != nil {
		t.Fatalf("Load real tools: %v", err)
	}
	essential := []string{"nmap", "nuclei", "httpx", "curl"}
	for _, name := range essential {
		if _, ok := r.Get(name); !ok {
			t.Errorf("essential tool %s not loaded", name)
		}
	}
	if len(r.List()) < 10 {
		t.Fatalf("expected at least 10 tools, got %d", len(r.List()))
	}
}

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "toolsdata")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "agents_md")); err == nil {
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
