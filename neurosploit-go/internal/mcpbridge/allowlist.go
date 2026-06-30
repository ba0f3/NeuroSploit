package mcpbridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Allowlist stores persisted bash command approvals.
type Allowlist struct {
	Commands []string `json:"commands"`
	TrustAll bool     `json:"trust_all"`
}

// AllowDir returns the .neurosploit directory under cwd.
func AllowDir() string {
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, ".neurosploit")
}

// LoadAllowlist reads .neurosploit/bash_allowlist.json or returns empty defaults.
func LoadAllowlist() *Allowlist {
	path := filepath.Join(AllowDir(), "bash_allowlist.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return &Allowlist{Commands: []string{}}
	}
	var al Allowlist
	if err := json.Unmarshal(data, &al); err != nil {
		return &Allowlist{Commands: []string{}}
	}
	return &al
}

// Save writes the allowlist to disk.
func (a *Allowlist) Save() error {
	dir := AllowDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bash_allowlist.json"), data, 0644)
}

func (a *Allowlist) has(cmd string) bool {
	cmd = strings.ToLower(cmd)
	for _, c := range a.Commands {
		if strings.ToLower(c) == cmd {
			return true
		}
	}
	return false
}

// Permits reports whether all base commands may run.
// When tty is false, only whitelisted commands are allowed.
func (a *Allowlist) Permits(bases []string, sessionTrust bool) bool {
	if sessionTrust || a.TrustAll {
		return true
	}
	for _, b := range bases {
		if !a.has(b) {
			return false
		}
	}
	return len(bases) > 0
}

// AddCommand permanently allows a base command.
func (a *Allowlist) AddCommand(cmd string) error {
	if a.has(cmd) {
		return nil
	}
	a.Commands = append(a.Commands, cmd)
	return a.Save()
}

// PromptFunc returns an allow decision for interactive TTY prompts.
type PromptFunc func(cmd string) (allowOnce bool, alwaysAllow bool, trustSession bool, err error)

// CheckBashPermission evaluates whether a bash command may execute.
func CheckBashPermission(cmd string, al *Allowlist, sessionTrust bool, tty bool, prompt PromptFunc) error {
	bases, err := baseCommands(cmd)
	if err != nil {
		return fmt.Errorf("bash: parse error: %w", err)
	}
	if len(bases) == 0 {
		return fmt.Errorf("bash: empty command")
	}
	if al.Permits(bases, sessionTrust) {
		return nil
	}
	if !tty || prompt == nil {
		return fmt.Errorf("bash: command not allowlisted: %s", strings.Join(bases, ", "))
	}
	once, always, trust, err := prompt(strings.Join(bases, ", "))
	if err != nil {
		return err
	}
	if trust {
		al.TrustAll = true
		_ = al.Save()
		return nil
	}
	if always {
		for _, b := range bases {
			_ = al.AddCommand(b)
		}
		return nil
	}
	if once {
		return nil
	}
	return fmt.Errorf("bash: denied by user")
}
