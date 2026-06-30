package mcpbridge

import (
	"mvdan.cc/sh/v3/syntax"
	"strings"
)

// baseCommands parses a shell command string and returns the base command name
// for each simple command (first word of each pipeline segment).
func baseCommands(cmd string) ([]string, error) {
	prog, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, err
	}
	var bases []string
	syntax.Walk(prog, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := wordString(call.Args[0])
		if name != "" {
			bases = append(bases, name)
		}
		return true
	})
	return bases, nil
}

func wordString(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		if lit, ok := p.(*syntax.Lit); ok {
			b.WriteString(lit.Value)
		}
	}
	return strings.TrimSpace(b.String())
}
