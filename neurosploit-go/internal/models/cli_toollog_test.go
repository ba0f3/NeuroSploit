package models

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIToolLoggerRecord(t *testing.T) {
	dir := t.TempDir()
	log := &CLIToolLogger{Dir: dir}
	path := log.Record("Bash", map[string]interface{}{"command": "curl -s http://example.com"})
	if path == "" {
		t.Fatal("expected log path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "curl -s http://example.com") {
		t.Fatalf("log missing command: %s", body)
	}
	if !strings.HasPrefix(filepath.Base(path), "cli-run") {
		t.Fatalf("unexpected filename: %s", filepath.Base(path))
	}
}
