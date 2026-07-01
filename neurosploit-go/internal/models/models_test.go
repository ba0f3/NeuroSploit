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
	if strings.HasSuffix(path, ".mcp.json") == false {
		t.Fatalf("path = %q", path)
	}
}

func TestWriteCursorMCPConfig(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteCursorMCPConfig(dir, "")
	if err != nil {
		t.Fatalf("WriteCursorMCPConfig failed: %v", err)
	}
	want := filepath.Join(dir, ".cursor", "mcp.json")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "playwright") {
		t.Errorf("config missing playwright server")
	}
}

func TestCursorCLIArgs(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(repo, "runs", "ns-test")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	promptPath := filepath.Join(runDir, ".ns-prompt-test.md")
	if err := os.WriteFile(promptPath, []byte("instructions"), 0600); err != nil {
		t.Fatal(err)
	}

	args, workdir, err := cursorCLIArgs("auto", promptPath, "", repo, true)
	if err != nil {
		t.Fatal(err)
	}
	if workdir != runDir {
		t.Fatalf("workdir = %q, want %q", workdir, runDir)
	}
	if !containsAll(args, "--force", "--trust", "-p", "--workspace", repo, "--output-format", "stream-json") {
		t.Fatalf("missing headless flags: %v", args)
	}
	meta := args[len(args)-1]
	absPrompt, _ := filepath.Abs(promptPath)
	if !strings.Contains(meta, absPrompt) {
		t.Fatalf("meta prompt should reference file %q, got %q", absPrompt, meta)
	}

	mcpPath := filepath.Join(repo, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(mcpPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcpPath, []byte(`{"mcpServers":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	args, workdir, err = cursorCLIArgs("auto", promptPath, mcpPath, repo, true)
	if err != nil {
		t.Fatal(err)
	}
	if workdir != runDir {
		t.Fatalf("workdir = %q, want %q", workdir, runDir)
	}
	if !containsAll(args, "--approve-mcps") {
		t.Fatalf("missing --approve-mcps: %v", args)
	}
	if containsAll(args, "--mcp-config") {
		t.Fatalf("cursor must not use --mcp-config: %v", args)
	}
	if !containsAll(args, "--workspace", repo) {
		t.Fatalf("workspace should be repo root: %v", args)
	}
}

func TestToolEvent(t *testing.T) {
	got := toolEvent("Bash", map[string]interface{}{"command": "curl -s http://example.com"})
	if !strings.HasPrefix(got, "exec: curl") {
		t.Fatalf("toolEvent = %q", got)
	}
	got = toolEvent("Bash", map[string]interface{}{"command": "rm -rf /"})
	if !strings.HasPrefix(got, "danger:") {
		t.Fatalf("danger toolEvent = %q", got)
	}
}

func TestConsumeCLIStream(t *testing.T) {
	var lines []string
	emit := func(s string) { lines = append(lines, s) }
	in := strings.NewReader(`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"curl example.com"}}]}}
{"type":"result","result":"done","is_error":false}`)
	result, hadErr := consumeCLIStream(in, emit, nil)
	if result != "done" || hadErr != "" {
		t.Fatalf("result=%q hadErr=%q", result, hadErr)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "exec:") {
		t.Fatalf("emit lines = %v", lines)
	}
}

func TestSubscriptionConcurrency(t *testing.T) {
	refs := []ModelRef{{Provider: "cursor", Model: "auto"}}
	if got := SubscriptionConcurrency(refs, 8); got != 1 {
		t.Fatalf("cursor concurrency = %d, want 1", got)
	}
	refs = []ModelRef{{Provider: "anthropic", Model: "claude"}}
	if got := SubscriptionConcurrency(refs, 8); got != 3 {
		t.Fatalf("anthropic concurrency = %d, want 3", got)
	}
}

func TestImpliesSubscription(t *testing.T) {
	if !ImpliesSubscription("cursor") || !ImpliesSubscription("agent") {
		t.Fatal("cursor/agent should imply subscription")
	}
	if ImpliesSubscription("anthropic") || ImpliesSubscription("openrouter") {
		t.Fatal("API providers should not imply subscription")
	}
}

func TestApplyImpliedSubscription(t *testing.T) {
	if !ApplyImpliedSubscription(false, []string{"cursor:auto"}) {
		t.Fatal("cursor model should imply subscription")
	}
	if ApplyImpliedSubscription(false, []string{"openrouter:minimax/minimax-m3"}) {
		t.Fatal("openrouter should not imply subscription")
	}
	if !ApplyImpliedSubscription(true, []string{"openrouter:minimax/minimax-m3"}) {
		t.Fatal("explicit subscription should stay on")
	}
}

func TestWriteCLIPromptFile(t *testing.T) {
	dir := t.TempDir()
	path, err := writeCLIPromptFile(dir, "system\n\nuser `--rm -rf /`")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "system\n\nuser `--rm -rf /`" {
		t.Fatalf("prompt file content mismatch: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("prompt file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestParseCursorOutput(t *testing.T) {
	got, err := parseCursorOutput(`{"result":"ok","is_error":false}`)
	if err != nil || got != "ok" {
		t.Fatalf("parse json = %q, %v", got, err)
	}
	_, err = parseCursorOutput(`{"result":"fail","is_error":true}`)
	if err == nil {
		t.Fatal("expected error for is_error")
	}
	got, err = parseCursorOutput("plain text")
	if err != nil || got != "plain text" {
		t.Fatalf("plain fallback = %q, %v", got, err)
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
