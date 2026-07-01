package source

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/integrations"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/repl"
)

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// Resolve returns a local path to a repo: existing dir, or clone into base/repos/.
func Resolve(base, arg string) (string, error) {
	kind, target := classifyArg(arg)
	if kind == "local" {
		return target, nil
	}
	reposDir := filepath.Join(base, "repos")
	if err := os.MkdirAll(reposDir, 0755); err != nil {
		return "", err
	}
	name := sanitizeRepoName(repoNameFromURL(target))
	dest := filepath.Join(reposDir, name)
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		fmt.Fprintf(os.Stderr, "  [*] repo cache hit → %s (delete it to re-clone)\n", dest)
		return dest, nil
	}
	ig := integrations.Load(repl.ProjDir())
	cloneURL := ig.AuthedCloneURL(target)
	private := cloneURL != target
	fmt.Fprintf(os.Stderr, "  [*] cloning %s%s → %s\n", target, privateNote(private), dest)
	cmd := exec.Command("git", "clone", "--depth", "1", cloneURL, dest)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dest)
		return "", fmt.Errorf("git clone failed for %s: %w", target, err)
	}
	return dest, nil
}

func privateNote(private bool) string {
	if private {
		return " (private, via token)"
	}
	return ""
}

func classifyArg(arg string) (kind, resolved string) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "local", arg
	}
	if st, err := os.Stat(arg); err == nil && st.IsDir() {
		return "local", arg
	}
	if isGitURL(arg) {
		return "remote", arg
	}
	if isGitHubShorthand(arg) {
		return "remote", githubShorthandURL(arg)
	}
	return "local", arg
}

func isGitURL(arg string) bool {
	return strings.HasPrefix(arg, "http://") ||
		strings.HasPrefix(arg, "https://") ||
		strings.HasPrefix(arg, "git@") ||
		strings.HasPrefix(arg, "ssh://") ||
		strings.HasSuffix(arg, ".git")
}

func isGitHubShorthand(arg string) bool {
	if isGitURL(arg) {
		return false
	}
	if _, err := os.Stat(arg); err == nil {
		return false
	}
	if strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~") {
		return false
	}
	if strings.Count(arg, "/") != 1 {
		return false
	}
	for _, c := range arg {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._-/", c) {
			continue
		}
		return false
	}
	return true
}

func githubShorthandURL(arg string) string {
	return "https://github.com/" + arg
}

func repoNameFromURL(url string) string {
	u := strings.TrimSuffix(strings.TrimSpace(url), "/")
	u = strings.TrimSuffix(u, ".git")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		u = u[i+1:]
	}
	if u == "" {
		return "repo"
	}
	return u
}

func sanitizeRepoName(name string) string {
	s := sanitizeRe.ReplaceAllString(name, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "repo"
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}
