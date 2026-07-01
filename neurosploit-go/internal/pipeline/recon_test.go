package pipeline

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/toolloop"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

func TestExtractChatContentPipeline(t *testing.T) {
	raw := `{"choices":[{"message":{"content":"{\"tech\":{\"server\":\"nginx\"}}"}}]}`
	got := models.ExtractChatContent(raw)
	if got == raw || !strings.Contains(got, "nginx") {
		t.Fatalf("got %q", got)
	}
}

func TestFinalizeReconText(t *testing.T) {
	raw := "{\"choices\":[{\"message\":{\"content\":\"Here is recon:\\n```json\\n{\\\"tech\\\":{\\\"server\\\":\\\"nginx\\\"}}\\n```\"}}]}"
	got := finalizeReconText(raw)
	if got == raw || !strings.Contains(got, "nginx") {
		t.Fatalf("got %q", got)
	}
}

func TestFormatToolLog(t *testing.T) {
	log := formatToolLog([]toolloop.Observation{
		{Call: tools.ToolCall{Name: "httpx", Args: map[string]any{"url": "https://example.com"}}, Result: tools.ToolResult{Output: "200 OK"}},
		{Call: tools.ToolCall{Name: "subfinder"}, Result: tools.ToolResult{IsError: true, Error: "subfinder not found in PATH"}},
	})
	if !strings.Contains(log, "httpx") || !strings.Contains(log, "subfinder") || !strings.Contains(log, "error") {
		t.Fatalf("got %q", log)
	}
}
