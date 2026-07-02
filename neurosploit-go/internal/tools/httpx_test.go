package tools

import (
	"strings"
	"testing"
)

func TestAdaptHttpxPythonArgv(t *testing.T) {
	ResetHttpxFlavorCache()
	t.Setenv("NS_HTTPX_FLAVOR", "python")
	in := []string{"httpx", "-silent", "-status-code", "-title", "-tech-detect", "-u", "https://example.com", "-follow-redirects"}
	got := adaptToolArgv(Tool{Name: "httpx"}, in)
	want := "httpx https://example.com --follow-redirects"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAdaptHttpxProjectDiscoveryArgv(t *testing.T) {
	ResetHttpxFlavorCache()
	t.Setenv("NS_HTTPX_FLAVOR", "projectdiscovery")
	in := []string{"httpx", "-silent", "-u", "https://example.com", "-follow-redirects"}
	got := adaptToolArgv(Tool{Name: "httpx"}, in)
	if strings.Join(got, " ") != strings.Join(in, " ") {
		t.Fatalf("PD argv changed: %v", got)
	}
}

func TestBuildCommandHttpxProjectDiscovery(t *testing.T) {
	ResetHttpxFlavorCache()
	t.Setenv("NS_HTTPX_FLAVOR", "projectdiscovery")
	tool := Tool{
		Name:    "httpx",
		Command: "httpx",
		Args:    []string{"-silent", "-status-code", "-title", "-tech-detect"},
		Parameters: []Parameter{
			{Name: "target", Type: "string", Required: true, Flag: "-u", Format: "flag", TargetFormat: "url"},
			{Name: "follow_redirects", Type: "bool", Default: true, Flag: "-follow-redirects", Format: "flag"},
		},
	}
	argv, err := BuildCommand(tool, map[string]any{"target": "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	if !strings.Contains(got, "-u https://example.com") {
		t.Fatalf("missing -u target: %q", got)
	}
	if !strings.Contains(got, "-silent") || !strings.Contains(got, "-status-code") {
		t.Fatalf("missing PD probe flags: %q", got)
	}
}
