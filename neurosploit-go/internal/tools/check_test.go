package tools

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestCheckBinaries(t *testing.T) {
	r := &Registry{tools: map[string]Tool{
		"curl": {Name: "curl", Command: "curl", InstallHint: "apt install curl"},
		"missing": {Name: "missing", Command: "definitely-not-a-real-binary-xyz", InstallHint: "n/a"},
	}}
	statuses := CheckBinaries(r)
	if len(statuses) != 2 {
		t.Fatalf("len = %d", len(statuses))
	}
	var curlFound, missingFound bool
	for _, s := range statuses {
		switch s.Tool {
		case "curl":
			curlFound = true
			if !s.Found {
				t.Fatal("curl should be on PATH in CI")
			}
		case "missing":
			missingFound = true
			if s.Found {
				t.Fatal("fake binary should be missing")
			}
		}
	}
	if !curlFound || !missingFound {
		t.Fatalf("statuses = %+v", statuses)
	}
}

func TestFormatCheckReport(t *testing.T) {
	var buf bytes.Buffer
	missing := FormatCheckReport(&buf, "Tools", []BinaryStatus{
		{Tool: "curl", Command: "curl", Found: true, Path: "/usr/bin/curl"},
		{Tool: "nmap", Command: "nmap", Found: false, Hint: "apt install nmap"},
	})
	if missing != 1 {
		t.Fatalf("missing = %d", missing)
	}
	out := buf.String()
	if !strings.Contains(out, "MISSING") || !strings.Contains(out, "apt install nmap") {
		t.Fatalf("output = %q", out)
	}
}

func TestUniqueCommands(t *testing.T) {
	r := &Registry{tools: map[string]Tool{
		"a": {Name: "a", Command: "curl"},
		"b": {Name: "b", Command: "curl"},
		"c": {Name: "c", Command: "nmap"},
	}}
	cmds := UniqueCommands(r)
	if len(cmds) != 2 || cmds[0] != "curl" || cmds[1] != "nmap" {
		t.Fatalf("cmds = %v", cmds)
	}
}

func TestCheckExtraBinaries(t *testing.T) {
	_, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}
	statuses := CheckExtraBinaries(DoctrineExtras)
	if len(statuses) == 0 {
		t.Fatal("expected extras")
	}
}
