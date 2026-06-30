package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	if m.Label() != "anthropic:gpt-5.5" {
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
