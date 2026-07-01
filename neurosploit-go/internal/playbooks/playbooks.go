package playbooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Playbook is a reusable, phase-driven pentest workflow.
type Playbook struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Tags        []string   `yaml:"tags,omitempty"`
	Variables   []Variable `yaml:"variables,omitempty"`
	Phases      []Phase    `yaml:"phases"`
}

// Variable describes a playbook input variable.
type Variable struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Required bool   `yaml:"required,omitempty"`
	Default  string `yaml:"default,omitempty"`
}

// Phase is one step of a playbook.
type Phase struct {
	Name         string   `yaml:"name"`
	Condition    string   `yaml:"condition,omitempty"`
	Tools        []string `yaml:"tools,omitempty"`
	Agents       []string `yaml:"agents,omitempty"`
	Skills       []string `yaml:"skills,omitempty"`
	PostAnalysis string   `yaml:"post_analysis,omitempty"`
}

// Registry is a loaded collection of playbooks.
type Registry struct {
	playbooks map[string]Playbook
}

// Load walks root/playbooks/*.yaml and returns a populated registry.
func Load(root string) (*Registry, error) {
	r := &Registry{playbooks: make(map[string]Playbook)}
	dir := filepath.Join(root, "playbooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var p Playbook
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if p.Name == "" {
			p.Name = strings.TrimSuffix(entry.Name(), ".yaml")
		}
		r.playbooks[p.Name] = p
	}
	return r, nil
}

// Get returns a playbook by name.
func (r *Registry) Get(name string) (Playbook, bool) {
	p, ok := r.playbooks[name]
	return p, ok
}

// List returns all playbooks sorted by name.
func (r *Registry) List() []Playbook {
	var names []string
	for n := range r.playbooks {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Playbook
	for _, n := range names {
		out = append(out, r.playbooks[n])
	}
	return out
}

// Engine runs a playbook against a target.
type Engine struct {
	ToolRegistry *tools.Registry
	Executor     tools.Executor
	SkillLibrary *skills.Library
	AgentRunner  func(ctx context.Context, name string, state map[string]any) ([]types.Finding, error)
	Progress     chan<- string
}

// Run executes the playbook with the given variables and returns final state and findings.
func (e *Engine) Run(ctx context.Context, pb Playbook, vars map[string]string) (map[string]any, []types.Finding, error) {
	state := map[string]any{}
	for _, v := range pb.Variables {
		val, ok := vars[v.Name]
		if !ok && v.Default != "" {
			val = v.Default
			ok = true
		}
		if v.Required && (!ok || strings.TrimSpace(val) == "") {
			return nil, nil, fmt.Errorf("missing required variable: %s", v.Name)
		}
		state[v.Name] = val
	}
	var findings []types.Finding
	for _, phase := range pb.Phases {
		if !e.evalCondition(phase.Condition, state) {
			e.emit(fmt.Sprintf("phase %s skipped (condition false)", phase.Name))
			continue
		}
		e.emit(fmt.Sprintf("phase %s start", phase.Name))
		for _, toolName := range phase.Tools {
			if e.ToolRegistry == nil || e.Executor == nil {
				e.emit(fmt.Sprintf("tool %s skipped (no registry/executor)", toolName))
				continue
			}
			tool, ok := e.ToolRegistry.Get(toolName)
			if !ok {
				e.emit(fmt.Sprintf("tool %s not found in registry", toolName))
				continue
			}
			e.emit(fmt.Sprintf("tool %s running", toolName))
			args := e.inferToolArgs(tool, state)
			res, err := e.Executor.Execute(ctx, tools.ToolCall{Name: toolName, Args: args})
			if err != nil {
				res = tools.ToolResult{IsError: true, Error: err.Error()}
			}
			state["tool_"+toolName] = res
			if res.IsError {
				e.emit(fmt.Sprintf("tool %s error: %s", toolName, truncate(res.Error, 120)))
			} else {
				e.emit(fmt.Sprintf("tool %s complete", toolName))
			}
		}
		for _, skillName := range phase.Skills {
			if e.SkillLibrary == nil {
				continue
			}
			if skill, ok := e.SkillLibrary.Get(skillName); ok {
				state["skill_"+skillName] = skill.PromptBlock()
			}
		}
		for _, agentName := range phase.Agents {
			if e.AgentRunner == nil {
				continue
			}
			af, err := e.AgentRunner(ctx, agentName, state)
			if err != nil {
				e.emit(fmt.Sprintf("agent %s error: %v", agentName, err))
				continue
			}
			findings = append(findings, af...)
			state["findings_count"] = len(findings)
		}
		if phase.PostAnalysis != "" {
			state["post_analysis_"+phase.Name] = phase.PostAnalysis
		}
		state[phase.Name] = true
		state["phase_"+phase.Name+"_done"] = true
		e.emit(fmt.Sprintf("phase %s complete", phase.Name))
	}
	state["findings_count"] = len(findings)
	return state, findings, nil
}

func (e *Engine) inferToolArgs(tool tools.Tool, state map[string]any) map[string]any {
	args := map[string]any{}
	for _, p := range tool.Parameters {
		if p.Name == "target" || p.Name == "host" || p.Name == "url" || p.Name == "domain" {
			if v, ok := state["target"]; ok {
				args[p.Name] = v
			}
		}
		if p.Name == "additional_args" && p.Default != nil {
			args[p.Name] = p.Default
		}
	}
	return args
}

func (e *Engine) evalCondition(cond string, state map[string]any) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return true
	}
	// Numeric comparison: key > value, key >= value, etc.
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if idx := strings.Index(cond, op); idx > 0 {
			key := strings.TrimSpace(cond[:idx])
			wantStr := strings.TrimSpace(cond[idx+len(op):])
			if v, ok := state[key]; ok {
				return compareState(v, wantStr, op)
			}
			if key == "findings_count" {
				return compareState(state["findings_count"], wantStr, op)
			}
			return false
		}
	}
	// Support simple boolean checks: state key is truthy.
	if v, ok := state[cond]; ok {
		switch val := v.(type) {
		case bool:
			return val
		case string:
			if b, err := strconv.ParseBool(val); err == nil {
				return b
			}
			return val != "" && !strings.EqualFold(val, "false") && !strings.EqualFold(val, "0")
		case int:
			return val > 0
		default:
			return true
		}
	}
	return false
}

func compareState(v any, wantStr, op string) bool {
	got := toFloat(v)
	want, err := strconv.ParseFloat(wantStr, 64)
	if err != nil {
		wantStr = strings.Trim(wantStr, "\"'")
		if fmt.Sprintf("%v", v) == wantStr {
			return op == "=="
		}
		return op == "!="
	}
	switch op {
	case ">":
		return got > want
	case ">=":
		return got >= want
	case "<":
		return got < want
	case "<=":
		return got <= want
	case "==":
		return got == want
	case "!=":
		return got != want
	}
	return false
}

func toFloat(v any) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case float64:
		return val
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

func (e *Engine) emit(msg string) {
	if e.Progress == nil {
		return
	}
	select {
	case e.Progress <- msg:
	default:
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
