package mcpbridge

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryUnknown(t *testing.T) {
	r := New()
	res := r.Execute(ToolCall{Name: "missing", ID: "1"})
	if !res.IsError {
		t.Errorf("expected error for unknown tool")
	}
}

func TestWriteAndReadFile(t *testing.T) {
	r := New()
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")
	res := r.Execute(ToolCall{Name: "write_file", ID: "2", Args: map[string]interface{}{
		"file_path": path,
		"content":   "hello",
	}})
	if res.IsError {
		t.Fatalf("write_file failed: %s", res.Error)
	}
	res = r.Execute(ToolCall{Name: "read_file", ID: "3", Args: map[string]interface{}{
		"file_path": path,
	}})
	if res.IsError {
		t.Fatalf("read_file failed: %s", res.Error)
	}
	if res.Output != "hello" {
		t.Errorf("read_file = %q, want hello", res.Output)
	}
}

func TestReadFileEscapesDir(t *testing.T) {
	r := New()
	res := r.Execute(ToolCall{Name: "read_file", ID: "4", Args: map[string]interface{}{
		"file_path": "../../etc/passwd",
	}})
	if !res.IsError || !strings.Contains(res.Error, "escapes") {
		t.Errorf("expected escape error, got %+v", res)
	}
}

func TestBashRejectsDangerous(t *testing.T) {
	r := New()
	res := r.Execute(ToolCall{Name: "bash", ID: "5", Args: map[string]interface{}{
		"command": "rm -rf /",
	}})
	if !res.IsError || !strings.Contains(res.Error, "dangerous") {
		t.Errorf("expected dangerous rejection, got %+v", res)
	}
}

func TestBashEcho(t *testing.T) {
	r := New()
	r.SessionTrust = true
	res := r.Execute(ToolCall{Name: "bash", ID: "6", Args: map[string]interface{}{
		"command": "echo hello",
	}})
	if res.IsError {
		t.Fatalf("bash failed: %s", res.Error)
	}
	if !strings.Contains(res.Output, "hello") {
		t.Errorf("bash output = %q", res.Output)
	}
}

func TestCustomHandler(t *testing.T) {
	r := New()
	r.Register("ping", func(call ToolCall) Result {
		return Result{Output: "pong"}
	})
	res := r.Execute(ToolCall{Name: "ping", ID: "7"})
	if res.IsError || res.Output != "pong" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestReadNonExistent(t *testing.T) {
	r := New()
	res := r.Execute(ToolCall{Name: "read_file", ID: "8", Args: map[string]interface{}{
		"file_path": filepath.Join(t.TempDir(), "does-not-exist.txt"),
	}})
	if !res.IsError {
		t.Errorf("expected error for missing file")
	}
}
