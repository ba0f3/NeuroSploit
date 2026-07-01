package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Tool describes a single external security tool that agents can invoke.
type Tool struct {
	Name             string        `yaml:"name"`
	Command          string        `yaml:"command"`
	Args             []string      `yaml:"args,omitempty"`
	Enabled          bool          `yaml:"enabled"`
	ShortDescription string        `yaml:"short_description"`
	Description      string        `yaml:"description"`
	Parameters       []Parameter   `yaml:"parameters,omitempty"`
	Timeout          time.Duration `yaml:"timeout,omitempty"`
	InstallHint      string        `yaml:"install_hint,omitempty"`
	Tags             []string      `yaml:"tags,omitempty"`
}

// Parameter describes one configurable argument of a tool.
type Parameter struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required,omitempty"`
	Default     any    `yaml:"default,omitempty"`
	Flag        string `yaml:"flag,omitempty"`
	Format      string `yaml:"format,omitempty"`
	Position    int    `yaml:"position,omitempty"`
}

// ToolCall is a request from an agent to run a tool.
type ToolCall struct {
	Name string
	ID   string
	Args map[string]any
}

// ToolResult is the outcome of executing a tool.
type ToolResult struct {
	Name     string
	ID       string
	Command  string
	Output   string
	Error    string
	ExitCode int
	Duration time.Duration
	IsError  bool
	LogPath  string
}

// Registry is a loaded collection of tool recipes.
type Registry struct {
	tools map[string]Tool
}

// Load walks root/toolsdata/**/*.yaml and returns a populated registry.
func Load(root string) (*Registry, error) {
	r := &Registry{tools: make(map[string]Tool)}
	dir := filepath.Join(root, "toolsdata")
	if _, err := os.Stat(dir); err != nil {
		return r, nil // empty registry if missing
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var t Tool
		if err := yaml.Unmarshal(data, &t); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if t.Name == "" {
			return fmt.Errorf("%s: missing tool name", path)
		}
		if t.Command == "" {
			return fmt.Errorf("%s: missing command", path)
		}
		if !t.Enabled {
			return nil
		}
		if t.Timeout == 0 {
			t.Timeout = 10 * time.Minute
		}
		r.tools[t.Name] = t
		return nil
	}); err != nil {
		return nil, err
	}
	return r, nil
}

// Without returns a copy of the registry with the named tools removed.
func (r *Registry) Without(names []string) *Registry {
	if r == nil || len(names) == 0 {
		return r
	}
	disabled := make(map[string]bool, len(names))
	for _, n := range names {
		disabled[strings.TrimSpace(n)] = true
	}
	out := &Registry{tools: make(map[string]Tool)}
	for n, t := range r.tools {
		if !disabled[n] {
			out.tools[n] = t
		}
	}
	return out
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (Tool, bool) {
	if r == nil || r.tools == nil {
		return Tool{}, false
	}
	t, ok := r.tools[name]
	return t, ok
}

// RegisterTool adds a tool to the registry (used in tests).
func (r *Registry) RegisterTool(t Tool) {
	if r.tools == nil {
		r.tools = make(map[string]Tool)
	}
	r.tools[t.Name] = t
}

// List returns all tools sorted by name.
func (r *Registry) List() []Tool {
	var names []string
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Tool
	for _, n := range names {
		out = append(out, r.tools[n])
	}
	return out
}

// FilterByTag returns tools that contain the given tag.
func (r *Registry) FilterByTag(tag string) []Tool {
	var out []Tool
	for _, t := range r.List() {
		for _, tg := range t.Tags {
			if strings.EqualFold(tg, tag) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// FunctionDefinition returns an OpenAI-compatible function schema for the tool.
func (t Tool) FunctionDefinition() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, p := range t.Parameters {
		if p.Name == "additional_args" {
			continue
		}
		schema := map[string]any{
			"type":        jsonType(p.Type),
			"description": p.Description,
		}
		if p.Default != nil {
			schema["default"] = p.Default
		}
		props[p.Name] = schema
		if p.Required {
			required = append(required, p.Name)
		}
	}
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        t.Name,
			"description": t.ShortDescription,
			"parameters": map[string]any{
				"type":                 "object",
				"properties":           props,
				"required":             required,
				"additionalProperties": false,
			},
		},
	}
}

func jsonType(t string) string {
	switch strings.ToLower(t) {
	case "int", "integer":
		return "integer"
	case "number", "float":
		return "number"
	case "bool", "boolean":
		return "boolean"
	default:
		return "string"
	}
}

// Executor runs tool calls.
type Executor interface {
	Execute(ctx context.Context, call ToolCall) (ToolResult, error)
}

// DefaultExecutor runs tools by looking up their recipes in a registry.
type DefaultExecutor struct {
	Registry *Registry
	Workdir  string
}

// Execute builds and runs the command for a tool call.
func (e *DefaultExecutor) Execute(ctx context.Context, call ToolCall) (ToolResult, error) {
	res := ToolResult{Name: call.Name, ID: call.ID}
	tool, ok := e.Registry.Get(call.Name)
	if !ok {
		res.IsError = true
		res.Error = fmt.Sprintf("unknown tool: %s", call.Name)
		return res, nil
	}
	args, err := BuildCommand(tool, call.Args)
	if err != nil {
		res.IsError = true
		res.Error = err.Error()
		return res, nil
	}
	cmdStr := strings.Join(args, " ")
	res.Command = cmdStr
	if isDangerous(cmdStr) {
		res.IsError = true
		res.Error = "dangerous command rejected"
		return res, nil
	}
	if _, err := exec.LookPath(args[0]); err != nil {
		res.IsError = true
		res.Error = fmt.Sprintf("%s not found in PATH: %s (hint: %s)", args[0], err, tool.InstallHint)
		return res, nil
	}

	if e.Workdir != "" {
		_ = os.MkdirAll(e.Workdir, 0755)
	}
	ctx2, cancel := context.WithTimeout(ctx, tool.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, args[0], args[1:]...)
	if e.Workdir != "" {
		cmd.Dir = e.Workdir
	}
	start := time.Now()
	out, err := cmd.CombinedOutput()
	res.Duration = time.Since(start)
	res.Output = string(out)
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		res.IsError = true
		res.Error = fmt.Sprintf("%v: %s", err, string(out))
	}
	return res, nil
}

// BuildCommand builds the final argv from a tool recipe and call arguments.
func BuildCommand(tool Tool, args map[string]any) ([]string, error) {
	argv := []string{tool.Command}
	argv = append(argv, tool.Args...)

	// positional args by position
	var positional [][2]int // [position, index in tool.Parameters]
	var flags []string
	var extras []string

	for i, p := range tool.Parameters {
		v, provided := args[p.Name]
		if p.Name == "additional_args" {
			if s, ok := v.(string); ok && s != "" {
				extras = append(extras, strings.Fields(s)...)
			}
			continue
		}
		if !provided && p.Default != nil {
			v = p.Default
			provided = true
		}
		if p.Required && !provided {
			return nil, fmt.Errorf("tool %s: missing required parameter %s", tool.Name, p.Name)
		}
		if !provided {
			continue
		}
		val := fmt.Sprintf("%v", v)
		switch p.Format {
		case "positional", "":
			positional = append(positional, [2]int{p.Position, i})
		case "flag", "combined":
			if p.Type == "bool" || p.Type == "boolean" {
				if b, ok := v.(bool); ok && b {
					flags = append(flags, p.Flag)
				}
			} else if p.Format == "combined" {
				flags = append(flags, fmt.Sprintf("%s%s", p.Flag, val))
			} else {
				flags = append(flags, p.Flag, val)
			}
		}
	}

	sort.Slice(positional, func(i, j int) bool {
		return positional[i][0] < positional[j][0]
	})

	// position 0 positional args go immediately after command + fixed args
	var pos0 []string
	for _, pos := range positional {
		if pos[0] == 0 {
			p := tool.Parameters[pos[1]]
			pos0 = append(pos0, fmt.Sprintf("%v", args[p.Name]))
		}
	}
	argv = append(argv, pos0...)
	argv = append(argv, flags...)
	for _, pos := range positional {
		if pos[0] != 0 {
			p := tool.Parameters[pos[1]]
			argv = append(argv, fmt.Sprintf("%v", args[p.Name]))
		}
	}
	argv = append(argv, extras...)
	return argv, nil
}

var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-rf\s+/`),
	regexp.MustCompile(`(?i)mkfs\b`),
	regexp.MustCompile(`(?i):\(\)\s*\{`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)>\s*/dev/`),
	regexp.MustCompile(`(?i)curl\s+.*\|\s*sh`),
	regexp.MustCompile(`(?i)wget\s+.*\|\s*sh`),
	regexp.MustCompile(`(?i)rm\s+-rf\s+~`),
	regexp.MustCompile(`(?i):\(\)\s*\{\s*:\|:\s*\};`),
}

func isDangerous(cmd string) bool {
	for _, re := range dangerousPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}
