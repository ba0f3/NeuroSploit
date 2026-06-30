package agents

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Agent represents a markdown specialist/meta agent loaded from agents_md/.
type Agent struct {
	Name   string
	Title  string
	CWE    string
	Kind   string
	System string
	User   string
}

// Library is the loaded agents_md/ library split into six categories.
type Library struct {
	Vulns  []Agent
	Meta   []Agent
	Recon  []Agent
	Code   []Agent
	Infra  []Agent
	Chains []Agent
}

// Total returns the total number of agents across all six categories.
func (lib Library) Total() int {
	return len(lib.Vulns) + len(lib.Meta) + len(lib.Recon) +
		len(lib.Code) + len(lib.Infra) + len(lib.Chains)
}

// Load reads the markdown agent library from <base>/agents_md/.
func Load(base string) Library {
	root := filepath.Join(base, "agents_md")
	return Library{
		Vulns:  loadDir(filepath.Join(root, "vulns"), "vuln"),
		Meta:   loadDir(filepath.Join(root, "meta"), "meta"),
		Recon:  loadDir(filepath.Join(root, "recon"), "recon"),
		Code:   loadDir(filepath.Join(root, "code"), "code"),
		Infra:  loadDir(filepath.Join(root, "infra"), "infra"),
		Chains: loadDir(filepath.Join(root, "chains"), "chain"),
	}
}

func loadDir(dir, kind string) []Agent {
	var out []Agent

	titleRe := regexp.MustCompile(`(?m)^#\s+(.+?)\s*$`)
	cweRe := regexp.MustCompile(`CWE-\d+`)
	userRe := regexp.MustCompile(`(?s)##\s*User Prompt\s*\n(.*?)(?:\n##\s|\z)`)
	sysRe := regexp.MustCompile(`(?s)##\s*System Prompt\s*\n(.*?)(?:\n##\s|\z)`)

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return out
	}

	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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
		content := string(text)

		name := filepath.Base(path)
		name = name[:len(name)-len(filepath.Ext(name))]

		title := name
		if m := titleRe.FindStringSubmatch(content); m != nil {
			title = m[1]
		}

		cwe := cweRe.FindString(content)

		var system, user string
		if m := sysRe.FindStringSubmatch(content); m != nil {
			system = m[1]
		}
		if m := userRe.FindStringSubmatch(content); m != nil {
			user = m[1]
		}

		out = append(out, Agent{
			Name:   name,
			Title:  title,
			CWE:    cwe,
			Kind:   kind,
			System: system,
			User:   user,
		})
		return nil
	})

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
