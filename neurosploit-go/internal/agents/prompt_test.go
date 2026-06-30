package agents

import "testing"

func TestRenderPrompt(t *testing.T) {
	got := RenderPrompt("Target {target}\nRecon: {recon_json}", map[string]string{
		"target":     "https://example.test",
		"recon_json": `{"tech":"nginx"}`,
	})
	want := "Target https://example.test\nRecon: {\"tech\":\"nginx\"}"
	if got != want {
		t.Fatalf("RenderPrompt = %q, want %q", got, want)
	}
}

func TestRenderPromptUnknownKeyLeftAlone(t *testing.T) {
	got := RenderPrompt("{unknown}", map[string]string{})
	if got != "{unknown}" {
		t.Fatalf("got %q", got)
	}
}
