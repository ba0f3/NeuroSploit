package types_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestFindingRoundTrip(t *testing.T) {
	original := types.Finding{
		ID:             "finding-1",
		Agent:          "sql-injection",
		Title:          "SQL Injection in login",
		Severity:       "Critical",
		CWE:            "CWE-89",
		CVSS:           "9.8",
		Endpoint:       "/api/login",
		Payload:        "' OR 1=1 --",
		Evidence:       "500 error with SQL syntax",
		Impact:         "Full database compromise",
		Remediation:    "Use parameterized queries",
		Confidence:     0.95,
		Validated:      true,
		Votes:          "3/4 confirmed",
		OWASP:          "A03:2021-Injection",
		Mitre:          "T1190",
		Stage:          "initial-access",
		Exploitability: "trivial",
		BusinessImpact: "Data breach",
		ChainsFrom:     []string{"recon-1"},
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal Finding: %v", err)
	}

	var decoded types.Finding
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal Finding: %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %+v\ndecoded:  %+v", original, decoded)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}

	wantKeys := []string{
		"id", "agent", "title", "severity", "cwe", "cvss", "endpoint", "payload",
		"evidence", "impact", "remediation", "confidence", "validated", "votes",
		"owasp", "mitre", "stage", "exploitability", "business_impact", "chains_from",
	}
	if len(raw) != len(wantKeys) {
		t.Fatalf("expected %d keys, got %d: %v", len(wantKeys), len(raw), raw)
	}
	for _, k := range wantKeys {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing JSON key: %s", k)
		}
	}
}

func TestDefaultFinding(t *testing.T) {
	f := types.DefaultFinding()
	if f.Severity != "Info" {
		t.Errorf("Severity: want Info, got %s", f.Severity)
	}
	if f.Confidence != 0 {
		t.Errorf("Confidence: want 0, got %f", f.Confidence)
	}
	if f.Validated != false {
		t.Errorf("Validated: want false, got %t", f.Validated)
	}
}

func TestNewRunConfig(t *testing.T) {
	cfg := types.NewRunConfig("http://t")
	if cfg.Target != "http://t" {
		t.Errorf("Target: want http://t, got %s", cfg.Target)
	}
	if !reflect.DeepEqual(cfg.Models, []string{"anthropic:claude-opus-4-8"}) {
		t.Errorf("Models: want [anthropic:claude-opus-4-8], got %v", cfg.Models)
	}
	if cfg.VoteN != 3 {
		t.Errorf("VoteN: want 3, got %d", cfg.VoteN)
	}
	if cfg.Concurrency != 8 {
		t.Errorf("Concurrency: want 8, got %d", cfg.Concurrency)
	}
	if cfg.MaxAgents != 0 {
		t.Errorf("MaxAgents: want 0, got %d", cfg.MaxAgents)
	}
	if cfg.Offline != false {
		t.Errorf("Offline: want false, got %t", cfg.Offline)
	}
	if cfg.Subscription != false {
		t.Errorf("Subscription: want false, got %t", cfg.Subscription)
	}
	if cfg.Verbose != false {
		t.Errorf("Verbose: want false, got %t", cfg.Verbose)
	}
	if cfg.Workdir != nil {
		t.Errorf("Workdir: want nil, got %v", *cfg.Workdir)
	}
	if cfg.RLPath != nil {
		t.Errorf("RLPath: want nil, got %v", *cfg.RLPath)
	}
	if cfg.Instructions != nil {
		t.Errorf("Instructions: want nil, got %v", *cfg.Instructions)
	}
	if cfg.Auth != nil {
		t.Errorf("Auth: want nil, got %v", *cfg.Auth)
	}
	if cfg.Repo != nil {
		t.Errorf("Repo: want nil, got %v", *cfg.Repo)
	}
	if !reflect.DeepEqual(cfg.Pinned, []string{}) {
		t.Errorf("Pinned: want empty slice, got %v", cfg.Pinned)
	}
}
