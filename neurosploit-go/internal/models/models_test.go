package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvidersCount(t *testing.T) {
	if got := len(Providers()); got != 15 {
		t.Errorf("Providers() = %d, want 15", got)
	}
}

func TestProviderCursor(t *testing.T) {
	var found bool
	for _, p := range Providers() {
		if p.Key == "cursor" {
			found = true
			if p.Kind != "cli" {
				t.Fatalf("kind = %s", p.Kind)
			}
		}
	}
	if !found {
		t.Fatal("cursor provider missing")
	}
	if !MCPSupported("cursor") {
		t.Fatal("cursor should support MCP")
	}
	if CLIBinaryFor("cursor") == "" {
		t.Fatal("CLIBinaryFor cursor empty")
	}
}

func TestModelRefParse(t *testing.T) {
	m := ModelRefParse("openai:gpt-5.5")
	if m.Provider != "openai" || m.Model != "gpt-5.5" {
		t.Errorf("ModelRefParse = %+v", m)
	}
	m = ModelRefParse("gpt-5.5")
	if m.Provider != "anthropic" || m.Model != "gpt-5.5" {
		t.Errorf("ModelRefParse without colon = %+v", m)
	}
	m = ModelRefParse("agent:auto")
	if m.Provider != "cursor" || m.Model != "auto" {
		t.Errorf("ModelRefParse agent alias = %+v", m)
	}
	if m.Label() != "cursor:auto" {
		t.Errorf("Label = %q", m.Label())
	}
}

func TestProviderFor(t *testing.T) {
	if p := ProviderFor("anthropic"); p == nil || p.Key != "anthropic" {
		t.Errorf("ProviderFor(anthropic) = %v", p)
	}
	if p := ProviderFor("unknown"); p != nil {
		t.Errorf("ProviderFor(unknown) should be nil")
	}
}

func TestMCPSupported(t *testing.T) {
	if !MCPSupported("anthropic") || !MCPSupported("openai") || !MCPSupported("cursor") || MCPSupported("xai") {
		t.Errorf("MCPSupported results incorrect")
	}
}

func TestChatSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("Authorization header = %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]interface{}{"content": "hello"}},
			},
		})
	}))
	defer server.Close()

	client := ChatClient{http: server.Client()}
	t.Setenv("LITELLM_BASE_URL", server.URL)
	t.Setenv("LITELLM_API_KEY", "test-key")

	got, err := client.Chat(context.Background(), ModelRef{Provider: "litellm", Model: "gpt-4o"}, "sys", "user")
	if err != nil {
		t.Fatalf("Chat failed: %v", err)
	}
	if got != "hello" {
		t.Errorf("Chat = %q, want hello", got)
	}
}

func TestChatMissingKey(t *testing.T) {
	client := NewChatClient()
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	if _, err := client.Chat(context.Background(), ModelRefParse("anthropic:claude-opus-4-8"), "s", "u"); err == nil {
		t.Errorf("expected error for missing key")
	}
}

func TestWriteMCPConfig(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteMCPConfig(dir, "")
	if err != nil {
		t.Fatalf("WriteMCPConfig failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "playwright") {
		t.Errorf("config missing playwright server")
	}
	cursorPath := filepath.Join(dir, ".cursor", "mcp.json")
	if _, err := os.Stat(cursorPath); err != nil {
		t.Fatalf(".cursor/mcp.json missing: %v", err)
	}
}

func TestCursorCLIArgs(t *testing.T) {
	args, workdir, err := cursorCLIArgs("auto", "hello", "")
	if err != nil {
		t.Fatal(err)
	}
	if workdir != "" {
		t.Fatalf("workdir = %q, want empty", workdir)
	}
	if args[len(args)-1] != "hello" {
		t.Fatalf("prompt not positional: %v", args)
	}
	if !containsAll(args, "--force", "--trust", "-p") {
		t.Fatalf("missing headless flags: %v", args)
	}

	dir := t.TempDir()
	mcpPath := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	args, workdir, err = cursorCLIArgs("auto", "probe", mcpPath)
	if err != nil {
		t.Fatal(err)
	}
	if workdir != dir {
		t.Fatalf("workdir = %q, want %q", workdir, dir)
	}
	if !containsAll(args, "--approve-mcps", "--mcp-config", workdir) {
		t.Fatalf("missing MCP flags: %v", args)
	}
}

func containsAll(slice []string, items ...string) bool {
	for _, item := range items {
		found := false
		for _, s := range slice {
			if s == item || strings.Contains(s, item) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestBinaryInPath(t *testing.T) {
	if !BinaryInPath("go") {
		t.Errorf("BinaryInPath(go) should be true")
	}
	if BinaryInPath("definitely-not-a-real-binary-xyz") {
		t.Errorf("BinaryInPath should be false for fake binary")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("hello world", 5); got != "hello…" {
		t.Errorf("truncate = %q", got)
	}
}
