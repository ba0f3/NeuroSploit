package mcpbridge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ToolCall represents an MCP tool invocation.
type ToolCall struct {
	Name string                 `json:"name"`
	ID   string                 `json:"id"`
	Args map[string]interface{} `json:"args"`
}

// Result is the outcome of a tool call.
type Result struct {
	ID      string `json:"id"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	IsError bool   `json:"is_error"`
}

// Handler is a function that executes a tool call.
type Handler func(ToolCall) Result

// Registry maps tool names to handlers.
type Registry struct {
	handlers map[string]Handler
}

// New creates a registry with the default built-in handlers.
func New() *Registry {
	r := &Registry{handlers: make(map[string]Handler)}
	r.Register("bash", handleBash)
	r.Register("read_file", handleReadFile)
	r.Register("write_file", handleWriteFile)
	r.Register("web_fetch", handleWebFetch)
	return r
}

// Register adds a handler for the named tool.
func (r *Registry) Register(name string, h Handler) {
	if r.handlers == nil {
		r.handlers = make(map[string]Handler)
	}
	r.handlers[name] = h
}

// Execute runs the handler for the given tool call.
func (r *Registry) Execute(call ToolCall) Result {
	if h, ok := r.handlers[call.Name]; ok {
		res := h(call)
		res.ID = call.ID
		return res
	}
	return Result{ID: call.ID, IsError: true, Error: fmt.Sprintf("unknown tool: %s", call.Name)}
}

func handleBash(call ToolCall) Result {
	cmdRaw, ok := call.Args["command"].(string)
	if !ok || cmdRaw == "" {
		return Result{IsError: true, Error: "bash: missing command"}
	}
	cmd := strings.TrimSpace(cmdRaw)
	if isDangerous(cmd) {
		return Result{IsError: true, Error: "bash: dangerous command rejected"}
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return Result{IsError: true, Error: "bash: empty command"}
	}
	ctx, cancel := withTimeout(60)
	defer cancel()
	c := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := c.CombinedOutput()
	if err != nil {
		return Result{IsError: true, Error: fmt.Sprintf("bash: %v: %s", err, string(out))}
	}
	return Result{Output: string(out)}
}

func handleReadFile(call ToolCall) Result {
	path, ok := call.Args["file_path"].(string)
	if !ok || path == "" {
		return Result{IsError: true, Error: "read_file: missing file_path"}
	}
	if hasTraversal(path) {
		return Result{IsError: true, Error: "read_file: path escapes working directory"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{IsError: true, Error: fmt.Sprintf("read_file: %v", err)}
	}
	return Result{Output: string(data)}
}

func handleWriteFile(call ToolCall) Result {
	path, ok := call.Args["file_path"].(string)
	if !ok || path == "" {
		return Result{IsError: true, Error: "write_file: missing file_path"}
	}
	content, _ := call.Args["content"].(string)
	if hasTraversal(path) {
		return Result{IsError: true, Error: "write_file: path escapes working directory"}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return Result{IsError: true, Error: fmt.Sprintf("write_file: %v", err)}
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return Result{IsError: true, Error: fmt.Sprintf("write_file: %v", err)}
	}
	return Result{Output: "written"}
}

func hasTraversal(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func handleWebFetch(call ToolCall) Result {
	url, ok := call.Args["url"].(string)
	if !ok || url == "" {
		return Result{IsError: true, Error: "web_fetch: missing url"}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return Result{IsError: true, Error: fmt.Sprintf("web_fetch: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return Result{IsError: true, Error: fmt.Sprintf("web_fetch: HTTP %d: %s", resp.StatusCode, string(body))}
	}
	return Result{Output: string(body)}
}

var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-rf\s+/`),
	regexp.MustCompile(`(?i)mkfs\b`),
	regexp.MustCompile(`(?i):\(\)\s*\{`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)>\s*/dev/`),
	regexp.MustCompile(`(?i)curl\s+.*\|\s*sh`),
	regexp.MustCompile(`(?i)wget\s+.*\|\s*sh`),
}

func isDangerous(cmd string) bool {
	for _, re := range dangerousPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

func withTimeout(seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
}
