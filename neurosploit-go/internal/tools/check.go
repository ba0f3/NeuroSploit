package tools

import (
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// BinaryStatus is the PATH probe result for one tool recipe binary.
type BinaryStatus struct {
	Tool    string
	Command string
	Found   bool
	Path    string
	Hint    string
}

// CheckBinaries probes PATH for each enabled tool's command binary.
func CheckBinaries(r *Registry) []BinaryStatus {
	if r == nil {
		return nil
	}
	var out []BinaryStatus
	for _, t := range r.List() {
		path, err := exec.LookPath(t.Command)
		out = append(out, BinaryStatus{
			Tool:    t.Name,
			Command: t.Command,
			Found:   err == nil,
			Path:    path,
			Hint:    strings.TrimSpace(t.InstallHint),
		})
	}
	return out
}

// ExtraBinary describes a helper binary referenced outside toolsdata recipes.
type ExtraBinary struct {
	Name string
	Hint string
}

// DoctrineExtras are common binaries mentioned in agent tooling doctrine but not
// always wrapped as recipes.
var DoctrineExtras = []ExtraBinary{
	{Name: "nc", Hint: "netcat — apt install netcat-openbsd / brew install netcat"},
	{Name: "bash", Hint: "required for MCP bash bridge"},
}

// CheckExtraBinaries probes doctrine helper binaries.
func CheckExtraBinaries(extras []ExtraBinary) []BinaryStatus {
	var out []BinaryStatus
	for _, e := range extras {
		path, err := exec.LookPath(e.Name)
		out = append(out, BinaryStatus{
			Tool:    e.Name,
			Command: e.Name,
			Found:   err == nil,
			Path:    path,
			Hint:    e.Hint,
		})
	}
	return out
}

// FormatCheckReport prints a status table and returns the number of missing binaries.
func FormatCheckReport(w io.Writer, title string, statuses []BinaryStatus) int {
	if len(statuses) == 0 {
		return 0
	}
	missing := 0
	fmt.Fprintf(w, "%s\n", title)
	for _, s := range statuses {
		status := "ok"
		detail := s.Path
		if !s.Found {
			missing++
			status = "MISSING"
			detail = s.Hint
			if detail == "" {
				detail = "not on PATH"
			}
		}
		fmt.Fprintf(w, "  %-14s %-10s %-7s %s\n", s.Tool, s.Command, status, detail)
	}
	fmt.Fprintln(w)
	return missing
}

// UniqueCommands returns sorted distinct command names from a registry.
func UniqueCommands(r *Registry) []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, t := range r.List() {
		seen[t.Command] = true
	}
	var cmds []string
	for c := range seen {
		cmds = append(cmds, c)
	}
	sort.Strings(cmds)
	return cmds
}
