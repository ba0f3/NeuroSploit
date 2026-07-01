package engagement

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestApplyCredsHostInstruction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("ssh:\n  host: 10.0.0.1\n  user: root\n  password: x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := types.NewRunConfig("10.0.0.1")
	if err := ApplyCreds(context.Background(), &cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.Instructions == nil || !strings.Contains(*cfg.Instructions, "SSH ACCESS") {
		t.Fatalf("instructions = %v", cfg.Instructions)
	}
}

func TestApplyCredsAutoLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := fmt.Sprintf("login:\n  url: %s\n  method: POST\n", srv.URL)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := types.NewRunConfig("http://app")
	if err := ApplyCreds(context.Background(), &cfg, path); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth == nil {
		t.Fatal("expected auth from auto-login")
	}
}

func TestApplyCredsEmptyPath(t *testing.T) {
	cfg := types.NewRunConfig("http://x")
	if err := ApplyCreds(context.Background(), &cfg, ""); err != nil {
		t.Fatal(err)
	}
}
