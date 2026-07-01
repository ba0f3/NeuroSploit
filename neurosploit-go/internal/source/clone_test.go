package source

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/integrations"
)

func TestGitCloneArgsExcludeToken(t *testing.T) {
	auth := integrations.CloneAuth{
		URL:      "https://github.com/acme/repo",
		Username: "x-access-token",
		Password: "super-secret-token",
	}
	cmd := exec.Command("git", "clone", "--depth", "1", auth.URL, "/tmp/dest")
	for _, arg := range cmd.Args {
		if strings.Contains(arg, auth.Password) {
			t.Fatalf("token leaked in argv: %q", arg)
		}
	}
}

func TestWriteAskpassScript(t *testing.T) {
	path, cleanup, err := writeAskpassScript()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if path == "" {
		t.Fatal("expected script path")
	}
}
