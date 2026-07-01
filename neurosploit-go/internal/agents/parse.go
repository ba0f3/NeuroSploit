package agents

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	titleRe         = regexp.MustCompile(`(?m)^#\s+(.+?)\s*$`)
	cweRe           = regexp.MustCompile(`CWE-\d+`)
	userRe          = regexp.MustCompile(`(?s)##\s*User Prompt\s*\n(.*?)(?:\n##\s|\z)`)
	sysRe           = regexp.MustCompile(`(?s)##\s*System Prompt\s*\n(.*?)(?:\n##\s|\z)`)
	toolsRe         = regexp.MustCompile(`(?s)##\s*Tools\s*\n(.*?)(?:\n##\s|\z)`)
	skillsRe        = regexp.MustCompile(`(?s)##\s*Skills\s*\n(.*?)(?:\n##\s|\z)`)
	schemaRe        = regexp.MustCompile(`(?s)##\s*Output Schema\s*\n(.*?)(?:\n##\s|\z)`)
	preconditionsRe = regexp.MustCompile(`(?s)##\s*Preconditions\s*\n(.*?)(?:\n##\s|\z)`)
)

func parseAgentFile(name, kind, content string) Agent {
	title := name
	if m := titleRe.FindStringSubmatch(content); m != nil {
		title = m[1]
	}
	cwe := cweRe.FindString(content)
	var system, user, toolsSection, skillsSection, schemaSection, precondSection string
	if m := sysRe.FindStringSubmatch(content); m != nil {
		system = strings.TrimSpace(m[1])
	}
	if m := userRe.FindStringSubmatch(content); m != nil {
		user = strings.TrimSpace(m[1])
	}
	if m := toolsRe.FindStringSubmatch(content); m != nil {
		toolsSection = strings.TrimSpace(m[1])
	}
	if m := skillsRe.FindStringSubmatch(content); m != nil {
		skillsSection = strings.TrimSpace(m[1])
	}
	if m := schemaRe.FindStringSubmatch(content); m != nil {
		schemaSection = strings.TrimSpace(m[1])
	}
	if m := preconditionsRe.FindStringSubmatch(content); m != nil {
		precondSection = strings.TrimSpace(m[1])
	}
	return Agent{
		Name:          name,
		Title:         title,
		CWE:           cwe,
		Kind:          kind,
		System:        system,
		User:          user,
		Tools:         splitList(toolsSection),
		Skills:        splitList(skillsSection),
		OutputSchema:  schemaSection,
		Preconditions: splitList(precondSection),
	}
}

func loadDir(dir, kind string) []Agent {
	var out []Agent

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return out
	}

	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		if d.IsDir() {
			return filepath.SkipDir
		}
		if filepath.Ext(d.Name()) != ".md" {
			return nil
		}

		text, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		name := filepath.Base(path)
		name = name[:len(name)-len(filepath.Ext(name))]
		out = append(out, parseAgentFile(name, kind, string(text)))
		return nil
	}); err != nil {
		return out
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func loadLibraryFromRoot(root string) Library {
	return Library{
		Vulns:  loadDir(filepath.Join(root, "vulns"), "vuln"),
		Meta:   loadDir(filepath.Join(root, "meta"), "meta"),
		Recon:  loadDir(filepath.Join(root, "recon"), "recon"),
		Code:   loadDir(filepath.Join(root, "code"), "code"),
		Infra:  loadDir(filepath.Join(root, "infra"), "infra"),
		Chains: loadDir(filepath.Join(root, "chains"), "chain"),
	}
}

// splitList splits a comma/newline separated list into trimmed non-empty strings.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		for _, line := range strings.Split(part, "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "-")
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}
