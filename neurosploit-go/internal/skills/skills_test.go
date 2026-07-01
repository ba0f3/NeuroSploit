package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSkills(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "skills_md", "demo"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "skills_md", "demo", "SKILL.md"), []byte(`---
name: demo
description: A demo skill.
tags: [web, xss]
tools: [dalfox]
---
# Demo
Run dalfox against the target.
`), 0644)

	lib, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s, ok := lib.Get("demo")
	if !ok {
		t.Fatal("expected demo skill")
	}
	if s.Description != "A demo skill." {
		t.Fatalf("description = %q", s.Description)
	}
	if len(s.Tools) != 1 || s.Tools[0] != "dalfox" {
		t.Fatalf("tools = %v", s.Tools)
	}
	if !strings.Contains(s.Body, "dalfox") {
		t.Fatalf("body = %q", s.Body)
	}
}

func TestLoadRealSkills(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	lib, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(lib.List()) < 5 {
		t.Fatalf("expected at least 5 skills, got %d", len(lib.List()))
	}
	if _, ok := lib.Get("network_recon"); !ok {
		t.Fatal("expected network_recon skill")
	}
}

func TestPromptBlock(t *testing.T) {
	s := Skill{Name: "xss", Description: "Find XSS", Tools: []string{"dalfox"}, Body: "Run dalfox."}
	block := s.PromptBlock()
	if !strings.Contains(block, "SKILL: xss") || !strings.Contains(block, "dalfox") {
		t.Fatalf("unexpected block: %s", block)
	}
}

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "skills_md")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "agents_md")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
