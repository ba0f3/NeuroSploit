package engagement

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/playbooks"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeTarget makes a filesystem-safe slug from a URL or path.
func SanitizeTarget(target string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	s = strings.TrimRight(s, "/")
	s = sanitizeRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		return "target"
	}
	return s
}

// BuildPool constructs a model pool for a live engagement.
func BuildPool(cfg types.RunConfig, mcp bool, workdir, base string) *pool.ModelPool {
	var refs []models.ModelRef
	for _, s := range cfg.Models {
		refs = append(refs, models.ModelRefParse(s))
	}
	mcpConfig := ""
	if mcp && cfg.Subscription && len(refs) > 0 && models.MCPSupported(refs[0].Provider) {
		_ = models.EnsurePlaywrightMCP(cfg.Verbose)
		if models.UsesCursorCLI(refs) {
			mcpConfig, _ = models.WriteCursorMCPConfig(base, "")
		} else {
			mcpConfig, _ = models.WriteMCPConfig(workdir, "")
		}
	}
	concurrency := cfg.Concurrency
	if cfg.Subscription {
		concurrency = models.SubscriptionConcurrency(refs, concurrency)
	}
	p := pool.WithAuth(refs, concurrency, cfg.Subscription, mcpConfig)
	client := models.NewChatClient()
	client.Verbose = cfg.Verbose
	if models.UsesCursorCLI(refs) {
		client.CursorWorkspace = base
	}
	client.CLIToolLog = &models.CLIToolLogger{Dir: filepath.Join(workdir, "tools")}
	p.Client = client
	p.CLITimeout = pool.ResolveCLITimeout(cfg)
	return p
}

// PrepareWorkdir sets cfg.Workdir and cfg.RLPath for a new run.
func PrepareWorkdir(base string, cfg *types.RunConfig) (string, error) {
	workdir := filepath.Join("runs", fmt.Sprintf("ns-%d-%s", time.Now().Unix(), SanitizeTarget(cfg.Target)))
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return "", err
	}
	cfg.Workdir = &workdir
	rlPath := filepath.Join(base, "data", "rl_state_go.json")
	cfg.RLPath = &rlPath
	_ = os.MkdirAll(filepath.Dir(rlPath), 0755)
	return workdir, nil
}

// Execute runs the pipeline for the given mode and returns output.
// progress receives live status lines; stub bypasses live model calls when non-nil.
func Execute(ctx context.Context, base string, cfg types.RunConfig, mode string, mcp bool, stub pipeline.PoolCaller, progress chan<- string) pipeline.RunOutput {
	cfg.Subscription = models.ApplyImpliedSubscription(cfg.Subscription, cfg.Models)
	lib := agents.Load(base)
	if _, err := PrepareWorkdir(base, &cfg); err != nil {
		if progress != nil {
			progress <- fmt.Sprintf("error: %v", err)
		}
		return pipeline.RunOutput{Target: cfg.Target}
	}
	workdir := *cfg.Workdir

	if cfg.Subscription {
		var refs []models.ModelRef
		for _, s := range cfg.Models {
			refs = append(refs, models.ModelRefParse(s))
		}
		cfg.Concurrency = models.SubscriptionConcurrency(refs, cfg.Concurrency)
	}

	var p pipeline.PoolCaller
	if stub != nil {
		p = stub
	} else {
		p = BuildPool(cfg, mcp, workdir, base)
	}

	// Load external tools, skills, and playbooks.
	toolReg, _ := tools.Load(base)
	toolReg = toolReg.Without(cfg.DisableTools)
	var executor tools.Executor
	if stub != nil {
		executor = offlineToolExecutor{}
	} else {
		executor = &tools.DefaultExecutor{Registry: toolReg, Workdir: workdir}
		if cfg.ToolTimeout > 0 {
			executor = &timeoutExecutor{Executor: executor, timeout: time.Duration(cfg.ToolTimeout) * time.Minute}
		}
		if cfg.Interactive {
			executor = &interactiveExecutor{Executor: executor}
		}
		executor = &tools.FileLogExecutor{Dir: filepath.Join(workdir, "tools"), Inner: executor}
	}
	skillLib, _ := skills.Load(base)
	if mp, ok := p.(*pool.ModelPool); ok {
		mp.ToolRegistry = toolReg
		mp.ToolExecutor = executor
		mp.SkillLibrary = skillLib
	} else {
		p = &toolAwarePool{inner: p, tools: toolReg, executor: executor, skills: skillLib}
	}

	if cfg.Playbook != "" {
		pbReg, err := playbooks.Load(base)
		if err != nil {
			if progress != nil {
				progress <- fmt.Sprintf("playbook load error: %v", err)
			}
			return pipeline.RunOutput{Target: cfg.Target}
		}
		pb, ok := pbReg.Get(cfg.Playbook)
		if !ok {
			if progress != nil {
				progress <- fmt.Sprintf("playbook %q not found", cfg.Playbook)
			}
			return pipeline.RunOutput{Target: cfg.Target}
		}
		return pipeline.RunPlaybook(ctx, cfg, lib, p, pb, progress)
	}

	switch mode {
	case "whitebox":
		return pipeline.RunWhitebox(ctx, cfg, lib, p, progress)
	case "greybox":
		return pipeline.RunGreybox(ctx, cfg, lib, p, progress)
	case "host":
		return pipeline.RunHost(ctx, cfg, lib, p, progress)
	default:
		return pipeline.Run(ctx, cfg, lib, p, progress)
	}
}

// interactiveExecutor wraps an executor and prompts before running commands.
type interactiveExecutor struct {
	Executor tools.Executor
}

func (i *interactiveExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	fmt.Fprintf(os.Stderr, "Run tool %s with args %v? [y/N] ", call.Name, call.Args)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return tools.ToolResult{Name: call.Name, ID: call.ID, IsError: true, Error: "skipped by user"}, nil
	}
	return i.Executor.Execute(ctx, call)
}

// timeoutExecutor overrides per-tool timeouts when cfg.ToolTimeout is set.
type timeoutExecutor struct {
	Executor tools.Executor
	timeout  time.Duration
}

func (t *timeoutExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	ctx2, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.Executor.Execute(ctx2, call)
}

// toolAwarePool attaches tools/skills to a PoolCaller that lacks them (e.g. offline stub).
type toolAwarePool struct {
	inner    pipeline.PoolCaller
	tools    *tools.Registry
	executor tools.Executor
	skills   *skills.Library
}

func (w *toolAwarePool) SetProgress(ch chan<- string) { w.inner.SetProgress(ch) }
func (w *toolAwarePool) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	return w.inner.Complete(label, task, system, user)
}
func (w *toolAwarePool) CompleteWithTools(label string, task pool.Task, system, user string, toolsJSON []map[string]any) (models.ModelRef, string, error) {
	return w.inner.CompleteWithTools(label, task, system, user, toolsJSON)
}
func (w *toolAwarePool) Vote(system, user string, n int, skip string) (int, int) {
	return w.inner.Vote(system, user, n, skip)
}
func (w *toolAwarePool) StopExploiting() bool     { return w.inner.StopExploiting() }
func (w *toolAwarePool) Tools() *tools.Registry   { return w.tools }
func (w *toolAwarePool) Executor() tools.Executor { return w.executor }
func (w *toolAwarePool) Skills() *skills.Library  { return w.skills }

// offlineToolExecutor returns stub output without running shell commands.
type offlineToolExecutor struct{}

func (offlineToolExecutor) Execute(_ context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	return tools.ToolResult{
		Name:   call.Name,
		ID:     call.ID,
		Output: fmt.Sprintf("[offline stub] %s", call.Name),
	}, nil
}
