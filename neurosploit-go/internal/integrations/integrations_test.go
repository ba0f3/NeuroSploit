package integrations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthedCloneURLGitHub(t *testing.T) {
	ig := Integrations{
		Github: GithubCfg{Enabled: true, TokenEnv: "TEST_GH_TOKEN"},
	}
	t.Setenv("TEST_GH_TOKEN", "secret")
	got := ig.AuthedCloneURL("https://github.com/acme/repo")
	want := "https://x-access-token:secret@github.com/acme/repo"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAuthedCloneURLDisabled(t *testing.T) {
	ig := Integrations{}
	url := "https://github.com/acme/repo"
	if ig.AuthedCloneURL(url) != url {
		t.Fatal("expected passthrough when disabled")
	}
}

func TestAuthedCloneURLGitLab(t *testing.T) {
	ig := Integrations{
		Gitlab: GitlabCfg{Enabled: true, TokenEnv: "TEST_GL_TOKEN", Base: "https://gitlab.com"},
	}
	t.Setenv("TEST_GL_TOKEN", "gltok")
	got := ig.AuthedCloneURL("https://gitlab.com/acme/repo")
	want := "https://oauth2:gltok@gitlab.com/acme/repo"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	ig := Load(t.TempDir())
	if ig.Github.TokenEnv != "GITHUB_TOKEN" {
		t.Fatalf("default github token_env = %q", ig.Github.TokenEnv)
	}
}

func TestLoadFromJSON(t *testing.T) {
	dir := t.TempDir()
	data := `{"github":{"enabled":true,"token_env":"MY_GH","api":"https://api.github.com"}}`
	if err := os.WriteFile(filepath.Join(dir, "integrations.json"), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	ig := Load(dir)
	if !ig.Github.Enabled || ig.Github.TokenEnv != "MY_GH" {
		t.Fatalf("loaded = %+v", ig.Github)
	}
}
