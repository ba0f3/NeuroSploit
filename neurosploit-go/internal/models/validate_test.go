package models

import (
	"os"
	"strings"
	"testing"
)

func TestValidatePanelAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	err := ValidatePanel([]ModelRef{{Provider: "openai", Model: "gpt-5.5"}})
	if err == nil || !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestValidatePanelOllamaNoKey(t *testing.T) {
	if err := ValidatePanel([]ModelRef{{Provider: "ollama", Model: "llama3"}}); err != nil {
		t.Fatalf("ollama should not require key: %v", err)
	}
}

func TestValidatePanelCLIMissing(t *testing.T) {
	// Use a provider whose binary is unlikely to be faked on PATH.
	err := ValidateModelRef(ModelRef{Provider: "grok", Model: "grok-4"})
	if err == nil {
		if BinaryInPath("grok") {
			t.Skip("grok on PATH")
		}
		t.Fatal("expected error when grok CLI missing")
	}
	if !strings.Contains(err.Error(), "grok") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidatePanelAggregates(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENROUTER_API_KEY", "")
	err := ValidatePanel([]ModelRef{
		{Provider: "openai", Model: "gpt-5.5"},
		{Provider: "openrouter", Model: "anthropic/claude-opus-4-8"},
	})
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "openai") || !strings.Contains(err.Error(), "openrouter") {
		t.Fatalf("expected both providers listed: %v", err)
	}
}

func TestValidatePanelWithKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	if err := ValidatePanel([]ModelRef{{Provider: "openai", Model: "gpt-5.5"}}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	_ = os.Unsetenv("OPENAI_API_KEY")
}
