package models

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAILoggerAppendsSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai.log")
	log := &AILogger{Path: path}

	p1 := log.Record(AICallRecord{
		Label:   "recon",
		Channel: "api",
		Model:   "anthropic:claude-opus-4-8",
		System:  "You are recon",
		User:    "scan http://example.com",
		Output:  `{"tech":"nginx"}`,
	})
	p2 := log.Record(AICallRecord{
		Label:   "sqli",
		Channel: "subscription",
		Model:   "anthropic:claude-opus-4-8",
		System:  "exploit",
		User:    "test",
		Output:  "[]",
	})
	if p1 != path || p2 != path {
		t.Fatalf("paths = %q %q, want %q", p1, p2, path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Count(text, "call: ") != 2 {
		t.Fatalf("expected 2 calls in one file, got:\n%s", text)
	}
	for _, want := range []string{"channel: api", "channel: subscription", `{"tech":"nginx"}`} {
		if !strings.Contains(text, want) {
			t.Fatalf("log missing %q:\n%s", want, text)
		}
	}
}

func TestAILoggerRecordError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.log")
	log := &AILogger{Path: path}
	log.Record(AICallRecord{
		Label:   "validate",
		Channel: "subscription",
		Model:   "anthropic:claude-opus-4-8",
		System:  "validator",
		User:    "finding",
		Err:     "rate limit",
	})
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "--- error ---\nrate limit") {
		t.Fatalf("expected error section: %s", body)
	}
}

func TestToolsSummary(t *testing.T) {
	s := ToolsSummary([]map[string]any{
		{"function": map[string]any{"name": "httpx"}},
		{"function": map[string]any{"name": "nmap"}},
	})
	if s != `["httpx","nmap"]` {
		t.Fatalf("got %q", s)
	}
}
