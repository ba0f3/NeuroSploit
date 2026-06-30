package rl

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

const eps = 1e-12

func TestUpdateConvergesToMax(t *testing.T) {
	s := &State{}
	for i := 0; i < 100; i++ {
		s.Update("a", 1.0)
	}
	got := s.Weight("a")
	if got > Wmax || math.Abs(got-Wmax) > eps {
		t.Fatalf("expected weight near %v, got %v", Wmax, got)
	}
	if s.Weights == nil {
		t.Fatal("Weights map should not be nil after update")
	}
}

func TestUpdateConvergesToMin(t *testing.T) {
	s := &State{}
	for i := 0; i < 100; i++ {
		s.Update("a", -1.0)
	}
	if got := s.Weight("a"); got != Wmin {
		t.Fatalf("expected weight to converge to %v, got %v", Wmin, got)
	}
}

func TestDefaultWeight(t *testing.T) {
	s := &State{}
	if got := s.Weight("missing"); got != 0.5 {
		t.Fatalf("expected default weight 0.5, got %v", got)
	}
}

func TestSeverityReward(t *testing.T) {
	cases := []struct {
		sev  string
		want float64
	}{
		{"Critical", 1.0},
		{"High", 0.7},
		{"Medium", 0.4},
		{"Low", 0.2},
		{"Info", 0.05},
		{"critical", 1.0}, // case-insensitive per spec
		{"HIGH", 0.7},
		{"Unknown", 0.05},
	}
	for _, tc := range cases {
		if got := SeverityReward(tc.sev); got != tc.want {
			t.Fatalf("SeverityReward(%q) = %v, want %v", tc.sev, got, tc.want)
		}
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "rl.json")

	s := &State{}
	for i := 0; i < 100; i++ {
		s.Update("agent1", 1.0)
	}
	for i := 0; i < 100; i++ {
		s.Update("agent2", -1.0)
	}
	s.Runs = 42

	if err := s.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded := Load(path)
	if loaded.Weights == nil {
		t.Fatal("loaded Weights map should not be nil")
	}
	if got := loaded.Weight("agent1"); got > Wmax || math.Abs(got-Wmax) > eps {
		t.Fatalf("expected agent1 weight near %v, got %v", Wmax, got)
	}
	if got := loaded.Weight("agent2"); got != Wmin {
		t.Fatalf("expected agent2 weight %v, got %v", Wmin, got)
	}
	if loaded.Runs != 42 {
		t.Fatalf("expected Runs 42, got %v", loaded.Runs)
	}
}

func TestLoadMissingFile(t *testing.T) {
	got := Load(filepath.Join(t.TempDir(), "missing", "rl.json"))
	if got.Weights == nil {
		t.Fatal("Load on missing file should return non-nil Weights map")
	}
	if len(got.Weights) != 0 {
		t.Fatalf("expected empty weights, got %v", got.Weights)
	}
	if got.Runs != 0 {
		t.Fatalf("expected Runs 0, got %v", got.Runs)
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rl.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	got := Load(path)
	if got.Weights == nil {
		t.Fatal("Load on malformed JSON should return non-nil Weights map")
	}
	if len(got.Weights) != 0 {
		t.Fatalf("expected empty weights, got %v", got.Weights)
	}
}

func TestClamp(t *testing.T) {
	if got := clamp(0.5, 0.0, 1.0); got != 0.5 {
		t.Fatalf("clamp(0.5, 0, 1) = %v, want 0.5", got)
	}
	if got := clamp(-0.5, 0.0, 1.0); got != 0.0 {
		t.Fatalf("clamp(-0.5, 0, 1) = %v, want 0.0", got)
	}
	if got := clamp(1.5, 0.0, 1.0); got != 1.0 {
		t.Fatalf("clamp(1.5, 0, 1) = %v, want 1.0", got)
	}
}
