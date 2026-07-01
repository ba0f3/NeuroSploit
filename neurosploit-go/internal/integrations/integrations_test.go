package integrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneAuthGitHub(t *testing.T) {
	ig := Integrations{
		Github: GithubCfg{Enabled: true, TokenEnv: "TEST_GH_TOKEN"},
	}
	t.Setenv("TEST_GH_TOKEN", "secret")
	auth := ig.CloneAuth("https://github.com/acme/repo")
	if auth.URL != "https://github.com/acme/repo" {
		t.Fatalf("url = %q", auth.URL)
	}
	if auth.Username != "x-access-token" || auth.Password != "secret" {
		t.Fatalf("auth = %+v", auth)
	}
	if strings.Contains(auth.URL, "secret") {
		t.Fatal("token must not appear in URL")
	}
}

func TestCloneAuthDisabled(t *testing.T) {
	ig := Integrations{}
	url := "https://github.com/acme/repo"
	auth := ig.CloneAuth(url)
	if auth.URL != url || auth.Password != "" {
		t.Fatalf("got %+v", auth)
	}
}

func TestCloneAuthGitLab(t *testing.T) {
	ig := Integrations{
		Gitlab: GitlabCfg{Enabled: true, TokenEnv: "TEST_GL_TOKEN", Base: "https://gitlab.com"},
	}
	t.Setenv("TEST_GL_TOKEN", "gltok")
	auth := ig.CloneAuth("https://gitlab.com/acme/repo")
	if auth.URL != "https://gitlab.com/acme/repo" || auth.Password != "gltok" {
		t.Fatalf("got %+v", auth)
	}
}

func TestValidatedGitlabHostRejectsRedirect(t *testing.T) {
	if _, ok := validatedGitlabHost("https://gitlab.com/redirect?to=evil"); ok {
		t.Fatal("path/query base should be rejected")
	}
	if _, ok := validatedGitlabHost("https://gitlab.com#@evil"); ok {
		t.Fatal("fragment base should be rejected")
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
