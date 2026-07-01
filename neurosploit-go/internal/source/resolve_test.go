package source

import (
	"strings"
	"testing"
)

func TestResolveLocalPath(t *testing.T) {
	dir := t.TempDir()
	got, err := Resolve(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("got %q want %q", got, dir)
	}
}

func TestIsGitHubShorthand(t *testing.T) {
	if !isGitHubShorthand("acme/repo") {
		t.Fatal("expected shorthand")
	}
	if isGitHubShorthand("/absolute/path") {
		t.Fatal("absolute path is not shorthand")
	}
	if isGitHubShorthand("http://github.com/a/b") {
		t.Fatal("URL is not shorthand")
	}
	if isGitHubShorthand("a/b/c") {
		t.Fatal("two slashes is not shorthand")
	}
}

func TestIsGitURL(t *testing.T) {
	if !isGitURL("https://github.com/a/b.git") {
		t.Fatal()
	}
	if !isGitURL("git@github.com:a/b.git") {
		t.Fatal()
	}
	if isGitURL("/local/path") {
		t.Fatal()
	}
}

func TestGitHubShorthandURL(t *testing.T) {
	if githubShorthandURL("acme/repo") != "https://github.com/acme/repo" {
		t.Fatal()
	}
}

func TestRepoNameFromURL(t *testing.T) {
	if repoNameFromURL("https://github.com/acme/DVWA.git/") != "DVWA" {
		t.Fatal(repoNameFromURL("https://github.com/acme/DVWA.git/"))
	}
}

func TestClassifyArgLocal(t *testing.T) {
	dir := t.TempDir()
	kind, resolved := classifyArg(dir)
	if kind != "local" || resolved != dir {
		t.Fatalf("kind=%q resolved=%q", kind, resolved)
	}
}

func TestClassifyArgShorthand(t *testing.T) {
	kind, resolved := classifyArg("acme/repo")
	if kind != "remote" || resolved != "https://github.com/acme/repo" {
		t.Fatalf("kind=%q resolved=%q", kind, resolved)
	}
}

func TestSanitizeRepoName(t *testing.T) {
	if strings.Contains(sanitizeRepoName("foo/bar!"), "!") {
		t.Fatal(sanitizeRepoName("foo/bar!"))
	}
}
