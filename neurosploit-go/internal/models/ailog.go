package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const aiLogSeparator = "\n================================================================================\n"

// AICallRecord is one model request/response for debugging.
type AICallRecord struct {
	Label   string
	Channel string // "api" or "subscription"
	Model   string
	System  string
	User    string
	Tools   string // optional JSON summary
	Output  string
	Err     string
}

// AILogger appends all AI prompts and responses to one file per run.
type AILogger struct {
	Path string
	mu   sync.Mutex
	n    int
}

// Record appends one AI call to the run log and returns the log file path.
func (l *AILogger) Record(rec AICallRecord) string {
	if l == nil || l.Path == "" {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.n++
	call := l.n
	if err := os.MkdirAll(filepath.Dir(l.Path), 0755); err != nil {
		return ""
	}

	var b strings.Builder
	if call > 1 {
		b.WriteString(aiLogSeparator)
	}
	fmt.Fprintf(&b, "time: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "call: %d\n", call)
	fmt.Fprintf(&b, "label: %s\n", rec.Label)
	fmt.Fprintf(&b, "channel: %s\n", rec.Channel)
	fmt.Fprintf(&b, "model: %s\n", rec.Model)
	fmt.Fprintf(&b, "\n--- system ---\n%s\n\n--- user ---\n%s\n", rec.System, rec.User)
	if rec.Tools != "" {
		fmt.Fprintf(&b, "\n--- tools ---\n%s\n", rec.Tools)
	}
	fmt.Fprintf(&b, "\n--- output ---\n%s\n", rec.Output)
	if rec.Err != "" {
		fmt.Fprintf(&b, "\n--- error ---\n%s\n", rec.Err)
	}

	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return ""
	}
	_, err = f.WriteString(b.String())
	_ = f.Close()
	if err != nil {
		return ""
	}
	return l.Path
}

// ToolsSummary returns a compact JSON description of tool definitions for logs.
func ToolsSummary(tools []map[string]any) string {
	if len(tools) == 0 {
		return ""
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if fn, ok := t["function"].(map[string]any); ok {
			if name, ok := fn["name"].(string); ok {
				names = append(names, name)
				continue
			}
		}
		if name, ok := t["name"].(string); ok {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		raw, _ := json.Marshal(names)
		return string(raw)
	}
	raw, err := json.Marshal(tools)
	if err != nil {
		return fmt.Sprintf("%d tool(s)", len(tools))
	}
	return string(raw)
}
