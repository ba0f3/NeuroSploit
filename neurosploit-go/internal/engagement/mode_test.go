package engagement

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
)

func TestDetectMode(t *testing.T) {
	cr := &creds.Creds{SSH: &creds.Ssh{Host: "10.0.0.1", User: "root", Password: "x"}}
	tests := []struct {
		repo, target string
		cr           *creds.Creds
		want         string
		wantErr      bool
	}{
		{"/repo", "http://app", nil, "greybox", false},
		{"/repo", "", nil, "whitebox", false},
		{"", "http://app", nil, "run", false},
		{"", "10.0.0.1", cr, "host", false},
		{"", "", nil, "", true},
	}
	for _, tc := range tests {
		got, err := DetectMode(tc.repo, tc.target, tc.cr)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("repo=%q target=%q expected error", tc.repo, tc.target)
			}
			continue
		}
		if err != nil {
			t.Fatalf("repo=%q target=%q: %v", tc.repo, tc.target, err)
		}
		if got != tc.want {
			t.Fatalf("repo=%q target=%q got %q want %q", tc.repo, tc.target, got, tc.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	if NormalizeURL("example.com") != "https://example.com" {
		t.Fatal("expected https prefix")
	}
	if NormalizeURL("http://x") != "http://x" {
		t.Fatal("expected http preserved")
	}
	if NormalizeURL("  https://y  ") != "https://y" {
		t.Fatal("expected trim")
	}
}

func TestIsHostTarget(t *testing.T) {
	cr := &creds.Creds{SSH: &creds.Ssh{Host: "10.0.0.1", User: "u", Password: "p"}}
	if !isHostTarget("10.0.0.1", cr) {
		t.Fatal("IP with ssh creds should be host")
	}
	if isHostTarget("http://app", cr) {
		t.Fatal("http URL should not be host")
	}
	if isHostTarget("10.0.0.1", nil) {
		t.Fatal("no creds should not be host")
	}
}

func TestModeLabel(t *testing.T) {
	if !strings.Contains(ModeLabel("greybox"), "greybox") {
		t.Fatal(ModeLabel("greybox"))
	}
}
