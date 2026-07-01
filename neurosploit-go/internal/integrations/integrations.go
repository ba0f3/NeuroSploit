package integrations

import (
	"encoding/json"
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

// AuthedCloneURL injects a token into an https git URL for private repo clone.
func (ig Integrations) AuthedCloneURL(url string) string {
	if ig.Github.Enabled {
		if rest, ok := strings.CutPrefix(url, "https://github.com/"); ok {
			if tok := ig.githubToken(); tok != "" {
				return "https://x-access-token:" + tok + "@github.com/" + rest
			}
		}
	}
	if ig.Gitlab.Enabled {
		host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(ig.Gitlab.Base, "https://"), "http://"), "/")
		prefix := "https://" + host + "/"
		if rest, ok := strings.CutPrefix(url, prefix); ok {
			if tok := ig.gitlabToken(); tok != "" {
				return "https://oauth2:" + tok + "@" + host + "/" + rest
			}
		}
	}
	return url
}
