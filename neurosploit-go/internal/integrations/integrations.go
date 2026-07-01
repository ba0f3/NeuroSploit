package integrations

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// GithubCfg holds GitHub integration settings (secrets via env var names only).
type GithubCfg struct {
	Enabled  bool   `json:"enabled"`
	TokenEnv string `json:"token_env"`
	API      string `json:"api"`
}

// DefaultGithubCfg returns disabled GitHub config with standard defaults.
func DefaultGithubCfg() GithubCfg {
	return GithubCfg{Enabled: false, TokenEnv: "GITHUB_TOKEN", API: "https://api.github.com"}
}

// GitlabCfg holds GitLab integration settings.
type GitlabCfg struct {
	Enabled  bool   `json:"enabled"`
	TokenEnv string `json:"token_env"`
	Base     string `json:"base"`
}

// DefaultGitlabCfg returns disabled GitLab config with standard defaults.
func DefaultGitlabCfg() GitlabCfg {
	return GitlabCfg{Enabled: false, TokenEnv: "GITLAB_TOKEN", Base: "https://gitlab.com"}
}

// Integrations persists to <project>/.neurosploit/integrations.json.
type Integrations struct {
	Github GithubCfg `json:"github"`
	Gitlab GitlabCfg `json:"gitlab"`
}

// CloneAuth holds a clean clone URL plus credentials passed via GIT_ASKPASS (not argv).
type CloneAuth struct {
	URL      string
	Username string
	Password string
}

// Load reads integrations.json from dir, or returns defaults if missing/invalid.
func Load(dir string) Integrations {
	path := filepath.Join(dir, "integrations.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return Integrations{Github: DefaultGithubCfg(), Gitlab: DefaultGitlabCfg()}
	}
	var ig Integrations
	if err := json.Unmarshal(data, &ig); err != nil {
		return Integrations{Github: DefaultGithubCfg(), Gitlab: DefaultGitlabCfg()}
	}
	if ig.Github.TokenEnv == "" {
		ig.Github.TokenEnv = "GITHUB_TOKEN"
	}
	if ig.Github.API == "" {
		ig.Github.API = "https://api.github.com"
	}
	if ig.Gitlab.TokenEnv == "" {
		ig.Gitlab.TokenEnv = "GITLAB_TOKEN"
	}
	if ig.Gitlab.Base == "" {
		ig.Gitlab.Base = "https://gitlab.com"
	}
	return ig
}

func env(name string) string {
	v, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return ""
	}
	return v
}

func (ig Integrations) githubToken() string { return env(ig.Github.TokenEnv) }
func (ig Integrations) gitlabToken() string { return env(ig.Gitlab.TokenEnv) }

// CloneAuth returns a clean HTTPS URL and credentials for private clone (no token in URL).
func (ig Integrations) CloneAuth(repoURL string) CloneAuth {
	out := CloneAuth{URL: repoURL}
	if ig.Github.Enabled {
		if rest, ok := strings.CutPrefix(repoURL, "https://github.com/"); ok {
			if tok := ig.githubToken(); tok != "" {
				out.URL = "https://github.com/" + rest
				out.Username = "x-access-token"
				out.Password = tok
				return out
			}
		}
	}
	if ig.Gitlab.Enabled {
		if host, ok := validatedGitlabHost(ig.Gitlab.Base); ok {
			prefix := "https://" + host + "/"
			if rest, ok := strings.CutPrefix(repoURL, prefix); ok {
				if tok := ig.gitlabToken(); tok != "" {
					out.URL = prefix + rest
					out.Username = "oauth2"
					out.Password = tok
					return out
				}
			}
		}
	}
	return out
}

func validatedGitlabHost(base string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", false
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	path := strings.Trim(u.Path, "/")
	if path != "" {
		return "", false
	}
	return u.Host, true
}
