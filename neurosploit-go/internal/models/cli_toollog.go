package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CLIToolLogger writes subscription-CLI tool_use events to workdir/tools/.
type CLIToolLogger struct {
	Dir string
	mu  sync.Mutex
	n   int
}

func (l *CLIToolLogger) Record(name string, input map[string]interface{}) string {
	if l == nil || l.Dir == "" {
		return ""
	}
	l.mu.Lock()
	l.n++
	run := l.n
	l.mu.Unlock()

	if err := os.MkdirAll(l.Dir, 0755); err != nil {
		return ""
	}
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	if safe == "" {
		safe = "tool"
	}
	path := filepath.Join(l.Dir, fmt.Sprintf("cli-run%03d-%s.log", run, safe))

	var b strings.Builder
	fmt.Fprintf(&b, "cli_tool: %s\n", name)
	fmt.Fprintf(&b, "run: %d\n", run)
	if len(input) > 0 {
		raw, _ := json.Marshal(input)
		fmt.Fprintf(&b, "input: %s\n", raw)
	}
	if name == "Bash" {
		if cmd, _ := input["command"].(string); cmd != "" {
			fmt.Fprintf(&b, "\n--- command ---\n%s\n", cmd)
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return ""
	}
	return path
}
