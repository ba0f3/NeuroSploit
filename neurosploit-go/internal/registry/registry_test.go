package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestAppendAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	r := New(path)
	if err := r.Append(types.Finding{ID: "f1", Title: "XSS", Severity: "High"}, true); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(data), "XSS") {
		t.Errorf("saved JSONL missing finding")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":"f1","title":"SQLi","severity":"Critical"}
{"id":"f2","title":"CSRF","severity":"Medium"}
`), 0644); err != nil {
		t.Fatal(err)
	}
	r := New("")
	if err := r.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(r.Findings()) != 2 {
		t.Errorf("findings = %d, want 2", len(r.Findings()))
	}
}

func TestDedupe(t *testing.T) {
	r := New("")
	if err := r.Append(types.Finding{ID: "f1", Severity: "High"}, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Append(types.Finding{ID: "f2", Severity: "Low"}, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Dedupe(func(f types.Finding) bool { return f.Severity == "High" }); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings()) != 1 || r.Findings()[0].ID != "f1" {
		t.Errorf("Dedupe kept wrong findings: %v", r.Findings())
	}
}

func TestUniqueFindings(t *testing.T) {
	r := New("")
	if err := r.Append(types.Finding{ID: "f1", Severity: "High", Votes: "confirmed"}, false); err != nil {
		t.Fatal(err)
	}
	if err := r.Append(types.Finding{ID: "f1", Severity: "High", Votes: "confirmed triaged"}, false); err != nil {
		t.Fatal(err)
	}
	unique := r.UniqueFindings()
	if len(unique) != 1 {
		t.Fatalf("unique = %d, want 1", len(unique))
	}
	if !strings.Contains(unique[0].Votes, "confirmed") || !strings.Contains(unique[0].Votes, "triaged") {
		t.Errorf("merged votes = %q", unique[0].Votes)
	}
}

func TestMergeVotes(t *testing.T) {
	r := New("")
	if err := r.Append(types.Finding{ID: "f1", Votes: "confirmed confirmed low"}, false); err != nil {
		t.Fatal(err)
	}
	r.MergeVotes()
	f := r.Findings()[0]
	if strings.Count(f.Votes, "confirmed") != 1 {
		t.Errorf("MergeVotes did not dedupe: %q", f.Votes)
	}
}
