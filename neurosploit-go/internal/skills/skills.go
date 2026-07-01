package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Skill represents a reusable testing capability.
type Skill struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags,omitempty"`
	Tools       []string `yaml:"tools,omitempty"`
	Body        string
}

// Library is a loaded collection of skills.
type Library struct {
	skills map[string]Skill
}

// Load walks root/skills_md/* and loads SKILL.md files.
func Load(root string) (*Library, error) {
	lib := &Library{skills: make(map[string]Skill)}
	dir := filepath.Join(root, "skills_md")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return lib, nil
		}
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name(), "SKILL.md")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		skill, err := parseSkill(entry.Name(), string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		lib.skills[skill.Name] = skill
	}
	return lib, nil
}

func parseSkill(dirName, content string) (Skill, error) {
	var s Skill
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, "---") {
		s.Name = dirName
		s.Body = content
		return s, nil
	}
	end := strings.Index(content[3:], "---")
	if end < 0 {
		s.Name = dirName
		s.Body = content
		return s, nil
	}
	front := content[3 : end+3]
	body := strings.TrimSpace(content[end+6:])
	if err := yaml.Unmarshal([]byte(front), &s); err != nil {
		return s, err
	}
	if s.Name == "" {
		s.Name = dirName
	}
	s.Body = body
	return s, nil
}

// Get returns a skill by name.
func (l *Library) Get(name string) (Skill, bool) {
	s, ok := l.skills[name]
	return s, ok
}

// List returns all skills sorted by name.
func (l *Library) List() []Skill {
	var names []string
	for n := range l.skills {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Skill
	for _, n := range names {
		out = append(out, l.skills[n])
	}
	return out
}

// FilterByTag returns skills containing the given tag.
func (l *Library) FilterByTag(tag string) []Skill {
	var out []Skill
	for _, s := range l.List() {
		for _, t := range s.Tags {
			if strings.EqualFold(t, tag) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// Render returns the skill body with optional variable substitution.
func (s Skill) Render(vars map[string]string) string {
	out := s.Body
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}

// PromptBlock returns a markdown block suitable for injection into a system prompt.
func (s Skill) PromptBlock() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## SKILL: %s\n\n", s.Name)
	fmt.Fprintf(&b, "%s\n\n", s.Description)
	if len(s.Tools) > 0 {
		fmt.Fprintf(&b, "Recommended tools: %s\n\n", strings.Join(s.Tools, ", "))
	}
	b.WriteString(s.Body)
	return b.String()
}
