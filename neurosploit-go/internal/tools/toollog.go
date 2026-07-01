package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type iterationKey struct{}

// ContextWithIteration tags a toolloop iteration for per-run log filenames.
func ContextWithIteration(ctx context.Context, iteration int) context.Context {
	if iteration < 0 {
		iteration = 0
	}
	return context.WithValue(ctx, iterationKey{}, iteration)
}

// IterationFromContext returns the toolloop iteration (0 when unset).
func IterationFromContext(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	v, ok := ctx.Value(iterationKey{}).(int)
	if !ok || v < 0 {
		return 0
	}
	return v
}

// FileLogExecutor wraps an Executor and writes one log file per invocation.
type FileLogExecutor struct {
	Dir   string
	Inner Executor
	mu    sync.Mutex
	runs  int
}

// Execute runs the inner executor and persists params, command, output, and exit code.
func (e *FileLogExecutor) Execute(ctx context.Context, call ToolCall) (ToolResult, error) {
	result, err := e.Inner.Execute(ctx, call)
	e.mu.Lock()
	e.runs++
	run := e.runs
	e.mu.Unlock()
	iter := IterationFromContext(ctx)
	if path, werr := WriteToolLog(e.Dir, iter, run, call, result); werr == nil {
		result.LogPath = path
	}
	return result, err
}

// WriteToolLog writes iter{NN}-run{NNN}-{tool}.log under dir.
func WriteToolLog(dir string, iteration, run int, call ToolCall, result ToolResult) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("tool log dir is empty")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	name := safeNameRe.ReplaceAllString(call.Name, "_")
	if name == "" {
		name = "tool"
	}
	filename := fmt.Sprintf("iter%02d-run%03d-%s.log", iteration, run, name)
	path := filepath.Join(dir, filename)

	var b strings.Builder
	fmt.Fprintf(&b, "tool: %s\n", call.Name)
	fmt.Fprintf(&b, "iteration: %d\n", iteration)
	fmt.Fprintf(&b, "run: %d\n", run)
	if call.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", call.ID)
	}
	if result.Command != "" {
		fmt.Fprintf(&b, "command: %s\n", result.Command)
	}
	if len(call.Args) > 0 {
		argsJSON, _ := json.Marshal(call.Args)
		fmt.Fprintf(&b, "params: %s\n", argsJSON)
	}
	fmt.Fprintf(&b, "exit_code: %d\n", result.ExitCode)
	if result.Duration > 0 {
		fmt.Fprintf(&b, "duration: %s\n", result.Duration.Round(time.Millisecond))
	}
	if result.IsError {
		fmt.Fprintf(&b, "status: error\n")
	} else {
		fmt.Fprintf(&b, "status: ok\n")
	}
	if result.Error != "" {
		fmt.Fprintf(&b, "\n--- error ---\n%s\n", result.Error)
	}
	if result.Output != "" {
		fmt.Fprintf(&b, "\n--- output ---\n%s\n", result.Output)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return "", err
	}
	return path, nil
}
