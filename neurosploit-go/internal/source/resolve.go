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
	auth := ig.CloneAuth(target)
	private := auth.Password != ""
	fmt.Fprintf(os.Stderr, "  [*] cloning %s%s → %s\n", target, privateNote(private), dest)
	if err := gitClone(auth, dest); err != nil {
		_ = os.RemoveAll(dest)
		return "", fmt.Errorf("git clone failed for %s: %w", target, err)
	}
	return dest, nil
}

func gitClone(auth integrations.CloneAuth, dest string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", auth.URL, dest)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if auth.Password != "" {
		script, cleanup, err := writeAskpassScript()
		if err != nil {
			return err
		}
		defer cleanup()
		cmd.Env = append(os.Environ(),
			"GIT_ASKPASS="+script,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_CLONE_USER="+auth.Username,
			"GIT_CLONE_PASS="+auth.Password,
		)
	}
	return cmd.Run()
}

func writeAskpassScript() (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "ns-git-askpass-*.sh")
	if err != nil {
		return "", nil, err
	}
	path = f.Name()
	script := "#!/bin/sh\ncase \"$1\" in\n*Username*|*username*) printf '%s\\n' \"$GIT_CLONE_USER\" ;;\n*) printf '%s\\n' \"$GIT_CLONE_PASS\" ;;\nesac\n"
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := f.Chmod(0700); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
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
