package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stubInner struct {
	n int
}

func (s *stubInner) Execute(_ context.Context, call ToolCall) (ToolResult, error) {
	s.n++
	return ToolResult{
		Name:     call.Name,
		ID:       call.ID,
		Command:  "echo ok",
		Output:   "ok",
		ExitCode: 0,
	}, nil
}

func TestWriteToolLogFilename(t *testing.T) {
	dir := t.TempDir()
	call := ToolCall{Name: "httpx", ID: "c1", Args: map[string]any{"url": "https://example.com"}}
	res := ToolResult{Command: "httpx https://example.com", Output: "200", ExitCode: 0}
	path, err := WriteToolLog(dir, 2, 5, call, res)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "iter02-run005-httpx.log" {
		t.Fatalf("path = %q", path)
	}
	body, _ := os.ReadFile(path)
	s := string(body)
	for _, want := range []string{"iteration: 2", "run: 5", "params:", "exit_code: 0", "--- output ---", "200"} {
		if !strings.Contains(s, want) {
			t.Fatalf("log missing %q:\n%s", want, s)
		}
	}
}

func TestFileLogExecutorRunSequence(t *testing.T) {
	dir := t.TempDir()
	inner := &stubInner{}
	logExec := &FileLogExecutor{Dir: dir, Inner: inner}
	ctx := ContextWithIteration(context.Background(), 1)
	for i := 0; i < 2; i++ {
		res, err := logExec.Execute(ctx, ToolCall{Name: "nmap", Args: map[string]any{"target": "x"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.LogPath == "" {
			t.Fatalf("run %d: missing LogPath", i+1)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 log files, got %d", len(entries))
	}
	if entries[0].Name() == entries[1].Name() {
		t.Fatal("log files should not overwrite")
	}
}
