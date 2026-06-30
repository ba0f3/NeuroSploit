package agents

import "strings"

// RenderPrompt replaces {key} placeholders in agent prompt templates.
func RenderPrompt(tmpl string, vars map[string]string) string {
	out := tmpl
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}
