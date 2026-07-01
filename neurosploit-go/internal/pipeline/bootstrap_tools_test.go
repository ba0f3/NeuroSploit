package pipeline

import (
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

func TestDefaultToolArgs(t *testing.T) {
	tool := tools.Tool{
		Name: "nmap",
		Parameters: []tools.Parameter{
			{Name: "target", Required: true},
		},
	}
	args, ok := defaultToolArgs(tool, "http://testasp.vulnweb.com/")
	if !ok {
		t.Fatal("expected ok")
	}
	if args["target"] != "http://testasp.vulnweb.com/" {
		t.Fatalf("target = %v", args["target"])
	}

	hostTool := tools.Tool{
		Name: "subfinder",
		Parameters: []tools.Parameter{
			{Name: "domain", Required: true},
		},
	}
	args, ok = defaultToolArgs(hostTool, "https://example.com:8443/path")
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
