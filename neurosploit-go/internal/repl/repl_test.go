package repl

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleLineSetTarget(t *testing.T) {
	s := NewSession()
	var buf bytes.Buffer
	if err := s.HandleLine("/target http://example.com", &buf); err != nil {
		t.Fatal(err)
	}
	if s.Target != "http://example.com" {
		t.Errorf("target = %q", s.Target)
	}
}

func TestHandleLineShow(t *testing.T) {
	s := NewSession()
	var buf bytes.Buffer
	if err := s.HandleLine("/show", &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "target:") {
		t.Errorf("show output missing target: %q", buf.String())
	}
}

func TestHandleLineHelp(t *testing.T) {
	s := NewSession()
	var buf bytes.Buffer
	if err := s.HandleLine("/help", &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Available commands") {
		t.Errorf("help output missing header: %q", buf.String())
	}
}

func TestHandleLineUnknown(t *testing.T) {
	s := NewSession()
	var buf bytes.Buffer
	if err := s.HandleLine("/foo", &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unknown command") {
		t.Errorf("unknown command output unexpected: %q", buf.String())
	}
}

func TestRunConfig(t *testing.T) {
	s := NewSession()
	s.Target = "http://example.com"
	s.Models = []string{"openai:gpt-5.5"}
	s.Offline = true
	cfg := s.RunConfig()
	if cfg.Target != "http://example.com" || cfg.Models[0] != "openai:gpt-5.5" || !cfg.Offline {
		t.Errorf("RunConfig = %+v", cfg)
	}
}

func TestRunEOF(t *testing.T) {
	s := NewSession()
	in := strings.NewReader("/quit\n")
	var buf bytes.Buffer
	if err := s.Run(in, &buf); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(buf.String(), "ns>") {
		t.Errorf("prompt missing: %q", buf.String())
	}
}
