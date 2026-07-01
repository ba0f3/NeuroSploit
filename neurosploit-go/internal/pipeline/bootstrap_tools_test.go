package pipeline

import (
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

func TestDefaultToolArgsUsesTargetFormat(t *testing.T) {
	nmap := tools.Tool{Name: "nmap", Parameters: []tools.Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	args, ok := defaultToolArgs(nmap, "https://example.com/app?q=1")
	if !ok {
		t.Fatal("expected default args")
	}
	if args["target"] != "example.com" {
		t.Fatalf("nmap target = %v want example.com", args["target"])
	}

	katana := tools.Tool{Name: "katana", Parameters: []tools.Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
	}}
	args, ok = defaultToolArgs(katana, "https://example.com/app?q=1")
	if !ok {
		t.Fatal("expected default args")
	}
	if args["target"] != "https://example.com/app?q=1" {
		t.Fatalf("katana target = %v want full URL", args["target"])
	}
}

func TestDefaultToolArgsRequiresFuzzMarkerForFfuf(t *testing.T) {
	ffuf := tools.Tool{Name: "ffuf", Parameters: []tools.Parameter{
		{Name: "url", Type: "string", Required: true, TargetFormat: "url_with_fuzz"},
	}}
	if _, ok := defaultToolArgs(ffuf, "https://example.com"); ok {
		t.Fatal("ffuf should not receive default args without FUZZ")
	}
}

func TestDefaultToolArgsLegacyDomain(t *testing.T) {
	hostTool := tools.Tool{
		Name: "subfinder",
		Parameters: []tools.Parameter{
			{Name: "domain", Required: true},
		},
	}
	args, ok := defaultToolArgs(hostTool, "https://example.com:8443/path")
	if !ok || args["domain"] != "example.com" {
		t.Fatalf("domain args = %v ok=%v", args, ok)
	}

	missing := tools.Tool{
		Name: "sqlmap",
		Parameters: []tools.Parameter{
			{Name: "url", Required: true},
			{Name: "data", Required: true},
		},
	}
	if _, ok := defaultToolArgs(missing, "http://x"); ok {
		t.Fatal("multi-required-param tool should not bootstrap")
	}
}

func TestTargetFromPrompt(t *testing.T) {
	user := "TOOLING...\n\nTarget: http://testasp.vulnweb.com\n"
	if got := targetFromPrompt(user); got != "http://testasp.vulnweb.com" {
		t.Fatalf("got %q", got)
	}
}
