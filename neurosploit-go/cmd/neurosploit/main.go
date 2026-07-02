package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/engagement"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/repl"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/source"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tui"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "neurosploit",
		Short: "NeuroSploit — multi-model autonomous pentest harness",
		Long: `NeuroSploit drives a pool of LLMs to autonomously test a target.
After recon it selects agents, runs them in parallel, then validates findings by cross-model voting before reporting.`,
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return repl.Run(findBase())
		},
	}
	root.AddCommand(runCmd(), whiteboxCmd(), greyboxCmd(), hostCmd(), tuiCmd(), toolsCmd(), agentsCmd(), modelsCmd())
	return root
}

func runCmd() *cobra.Command {
	var modelsFlag []string
	var maxAgents, voteN, chainDepth, toolLoopMaxIter int
	var offline, mcp, autoTools, interactive, autoSkills bool
	var credsPath, focus, playbook, skillsFlag, disableTools string
	var reconFlag, fromRun, reconCache string
	var verbose bool
	var toolTimeout, cliTimeout int

	cmd := &cobra.Command{
		Use:   "run <url>",
		Short: "Black-box recon → exploit → vote → report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := types.NewRunConfig(args[0])
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			cfg.VoteN = voteN
			cfg.ChainDepth = chainDepth
			cfg.ToolLoopMaxIter = toolLoopMaxIter
			cfg.Verbose = verbose
			cfg.AutoTools = autoTools
			cfg.Interactive = interactive
			cfg.AutoSkills = autoSkills
			cfg.Playbook = playbook
			cfg.ToolTimeout = toolTimeout
			cfg.CLITimeout = cliTimeout
			if skillsFlag != "" {
				cfg.Skills = strings.Split(skillsFlag, ",")
			}
			if disableTools != "" {
				cfg.DisableTools = strings.Split(disableTools, ",")
			}
			if focus != "" {
				cfg.Instructions = &focus
			}
			if err := applyReconFlags(&cfg, reconFlag, fromRun, reconCache); err != nil {
				return err
			}
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			if offline {
				cfg.Offline = false
				return runEngagement(cmd.Context(), cfg, mcp, "run", offlineStubPool{})
			}
			return runEngagement(cmd.Context(), cfg, mcp, "run", nil)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum agents to launch (0 = unlimited, run all selected)")
	cmd.Flags().IntVar(&voteN, "vote-n", 3, "Cross-model validation panel size")
	cmd.Flags().IntVar(&chainDepth, "chain-depth", types.DefaultChainDepth, "Attack-chaining rounds (post-exploitation pivots; 0 disables)")
	cmd.Flags().IntVar(&toolLoopMaxIter, "tool-loop-max-iter", types.DefaultToolLoopMaxIter, "Max ReAct tool-loop iterations per agent")
	cmd.Flags().BoolVar(&offline, "offline", false, "Offline self-test using stubbed pool")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable Playwright MCP if available")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().StringVar(&focus, "focus", "", "Focus instructions")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&autoTools, "auto-tools", true, "Automatically run tools from agent recipes (recon always uses tools when available)")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Prompt before executing each tool command")
	cmd.Flags().BoolVar(&autoSkills, "auto-skills", false, "Inject relevant skills into agent prompts")
	cmd.Flags().StringVar(&playbook, "playbook", "", "Run a named playbook instead of the default pipeline")
	cmd.Flags().StringVar(&skillsFlag, "skills", "", "Comma-separated skills to inject")
	cmd.Flags().StringVar(&disableTools, "disable-tools", "", "Comma-separated tools to disable")
	cmd.Flags().IntVar(&toolTimeout, "tool-timeout", 0, "Tool timeout in minutes (0 = recipe default; also extends CLI session if larger)")
	cmd.Flags().IntVar(&cliTimeout, "cli-timeout", 0, "Subscription/CLI agent session timeout in minutes (0 = 60; use for long sqlmap/nmap runs)")
	addReconFlags(cmd, &reconFlag, &fromRun, &reconCache)
	return cmd
}

func whiteboxCmd() *cobra.Command {
	var modelsFlag []string
	var maxAgents, voteN, chainDepth int
	var mcp, verbose bool
	var credsPath string
	var reconFlag, fromRun, reconCache string

	cmd := &cobra.Command{
		Use:   "whitebox <path|url>",
		Short: "White-box source review of a local path or git repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := types.NewRunConfig(args[0])
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			cfg.VoteN = voteN
			cfg.ChainDepth = chainDepth
			cfg.Verbose = verbose
			if err := applyReconFlags(&cfg, reconFlag, fromRun, reconCache); err != nil {
				return err
			}
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			return runEngagement(cmd.Context(), cfg, mcp, "whitebox", nil)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum agents")
	cmd.Flags().IntVar(&voteN, "vote-n", 2, "Cross-model validation panel size")
	cmd.Flags().IntVar(&chainDepth, "chain-depth", types.DefaultChainDepth, "Attack-chaining rounds (post-exploitation pivots; 0 disables)")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable MCP")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	addReconFlags(cmd, &reconFlag, &fromRun, &reconCache)
	return cmd
}

func greyboxCmd() *cobra.Command {
	var url string
	var modelsFlag []string
	var maxAgents, voteN, chainDepth int
	var offline, mcp, verbose bool
	var credsPath, focus string
	var reconFlag, fromRun, reconCache string

	cmd := &cobra.Command{
		Use:   "greybox <repo>",
		Short: "Review source and exploit the running app together",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base := findBase()
			repo, err := source.Resolve(base, args[0])
			if err != nil {
				return err
			}
			cfg := types.NewRunConfig(engagement.NormalizeURL(url))
			cfg.Repo = &repo
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			cfg.VoteN = voteN
			if cfg.VoteN == 0 {
				cfg.VoteN = 3
			}
			cfg.ChainDepth = chainDepth
			cfg.Verbose = verbose
			if focus != "" {
				cfg.Instructions = &focus
			}
			if err := applyReconFlags(&cfg, reconFlag, fromRun, reconCache); err != nil {
				return err
			}
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			stub := pipeline.PoolCaller(nil)
			if offline {
				stub = offlineStubPool{}
			}
			return runEngagement(cmd.Context(), cfg, mcp, "greybox", stub)
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "URL of the running application")
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum agents to launch")
	cmd.Flags().IntVar(&voteN, "vote-n", 3, "Cross-model validation panel size")
	cmd.Flags().IntVar(&chainDepth, "chain-depth", types.DefaultChainDepth, "Attack-chaining rounds (post-exploitation pivots; 0 disables)")
	cmd.Flags().BoolVar(&offline, "offline", false, "Offline self-test using stubbed pool")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable Playwright MCP if available")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().StringVar(&focus, "focus", "", "Focus instructions")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	_ = cmd.MarkFlagRequired("url")
	addReconFlags(cmd, &reconFlag, &fromRun, &reconCache)
	return cmd
}

func hostCmd() *cobra.Command {
	var modelsFlag []string
	var maxAgents, voteN, chainDepth int
	var offline, verbose bool
	var credsPath, focus string
	var reconFlag, fromRun, reconCache string

	cmd := &cobra.Command{
		Use:   "host <target>",
		Short: "Scan and test an infrastructure target (Linux/Windows/AD)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := types.NewRunConfig(args[0])
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			cfg.VoteN = voteN
			if cfg.VoteN == 0 {
				cfg.VoteN = 3
			}
			cfg.ChainDepth = chainDepth
			cfg.Verbose = verbose
			if focus != "" {
				cfg.Instructions = &focus
			}
			if err := applyReconFlags(&cfg, reconFlag, fromRun, reconCache); err != nil {
				return err
			}
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			stub := pipeline.PoolCaller(nil)
			if offline {
				stub = offlineStubPool{}
			}
			return runEngagement(cmd.Context(), cfg, false, "host", stub)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml (ssh/windows blocks)")
	cmd.Flags().StringVar(&focus, "focus", "", "Focus instructions")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum infra agents to launch")
	cmd.Flags().IntVar(&voteN, "vote-n", 3, "Cross-model validation panel size")
	cmd.Flags().IntVar(&chainDepth, "chain-depth", types.DefaultChainDepth, "Attack-chaining rounds (post-exploitation pivots; 0 disables)")
	cmd.Flags().BoolVar(&offline, "offline", false, "Offline self-test using stubbed pool")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	addReconFlags(cmd, &reconFlag, &fromRun, &reconCache)
	return cmd
}

func tuiCmd() *cobra.Command {
	var modelsFlag []string
	var chainDepth int
	var mcp, verbose bool
	var repoFlag, credsPath, focus string
	var reconFlag, fromRun, reconCache string

	cmd := &cobra.Command{
		Use:   "tui <url>",
		Short: "Mission Control TUI for a live engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base := findBase()
			mode := "run"
			cfg := types.NewRunConfig(engagement.NormalizeURL(args[0]))
			if repoFlag != "" {
				mode = "greybox"
				repo, err := source.Resolve(base, repoFlag)
				if err != nil {
					return err
				}
				cfg.Repo = &repo
			}
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = 0
			cfg.VoteN = 3
			cfg.ChainDepth = chainDepth
			cfg.Verbose = verbose
			if focus != "" {
				cfg.Instructions = &focus
			}
			if err := applyReconFlags(&cfg, reconFlag, fromRun, reconCache); err != nil {
				return err
			}
			if err := engagement.ApplyCreds(cmd.Context(), &cfg, credsPath); err != nil {
				return err
			}
			return tui.Run(base, cfg, mode, mcp)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().StringVar(&repoFlag, "repo", "", "Source repo path or GitHub URL (greybox mode)")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().StringVar(&focus, "focus", "", "Focus instructions")
	cmd.Flags().IntVar(&chainDepth, "chain-depth", types.DefaultChainDepth, "Attack-chaining rounds (post-exploitation pivots; 0 disables)")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable MCP")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	addReconFlags(cmd, &reconFlag, &fromRun, &reconCache)
	return cmd
}

func toolsCmd() *cobra.Command {
	var base string
	var extras, cli bool

	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Check pentest tool binaries on PATH",
		Long: `Verify that external tool binaries from toolsdata/ recipes are installed and on PATH.
Use before a live engagement to see what will degrade gracefully when missing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if base == "" {
				base = findBase()
			}
			reg, err := tools.Load(base)
			if err != nil {
				return err
			}
			missing := 0
			missing += tools.FormatCheckReport(os.Stdout, fmt.Sprintf("Tool recipes (%d)", len(reg.List())), tools.CheckBinaries(reg))
			if extras {
				missing += tools.FormatCheckReport(os.Stdout, "Doctrine helpers", tools.CheckExtraBinaries(tools.DoctrineExtras))
			}
			if cli {
				missing += formatCLIBackends(os.Stdout)
			}
			if missing > 0 {
				return fmt.Errorf("%d binary(ies) missing on PATH", missing)
			}
			fmt.Println("All checked binaries found on PATH.")
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "Repository root (default: auto-detect agents_md/)")
	cmd.Flags().BoolVar(&extras, "extras", true, "Also check doctrine helpers (nc, bash)")
	cmd.Flags().BoolVar(&cli, "cli", false, "Also check subscription CLI backends and npx (MCP)")
	return cmd
}

func formatCLIBackends(w io.Writer) int {
	type entry struct {
		label   string
		command string
		hint    string
	}
	entries := []entry{
		{"claude", models.CLIBinaryFor("claude"), "Anthropic Claude Code CLI"},
		{"codex", models.CLIBinaryFor("codex"), "OpenAI Codex CLI"},
		{"grok", models.CLIBinaryFor("grok"), "xAI Grok CLI"},
		{"agy", models.CLIBinaryFor("agy"), "Google Antigravity CLI"},
		{"cursor", models.CLIBinaryFor("cursor"), "Cursor Agent CLI"},
		{"npx", "npx", "Node.js npx — Playwright MCP"},
	}

	var statuses []tools.BinaryStatus
	for _, e := range entries {
		path, ok := "", false
		if e.command != "" {
			if p, err := exec.LookPath(e.command); err == nil {
				path, ok = p, true
			}
		}
		statuses = append(statuses, tools.BinaryStatus{
			Tool: e.label, Command: e.command, Found: ok, Path: path, Hint: e.hint,
		})
	}
	return tools.FormatCheckReport(w, "Subscription / MCP CLIs", statuses)
}

func agentsCmd() *cobra.Command {
	var base string
	var listOnly bool

	cmd := &cobra.Command{
		Use:   "agents",
		Short: "List available agents loaded from the agents_md directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if base == "" {
				base = findBase()
			}
			lib := agents.Load(base)
			if listOnly {
				fmt.Printf("Total agents: %d\n", lib.Total())
				for _, a := range allAgents(lib) {
					fmt.Printf("- %s (%s) %s\n", a.Title, a.Kind, a.CWE)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "Repository root")
	cmd.Flags().BoolVarP(&listOnly, "list", "l", true, "List agents")
	return cmd
}

func modelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "models",
		Short: "List supported model providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range models.Providers() {
				fmt.Printf("%-12s %s\n", p.Key, p.Label)
				for _, m := range p.Models {
					fmt.Printf("             %s\n", m)
				}
			}
			return nil
		},
	}
	return cmd
}

func allAgents(lib agents.Library) []agents.Agent {
	var out []agents.Agent
	out = append(out, lib.Vulns...)
	out = append(out, lib.Meta...)
	out = append(out, lib.Recon...)
	out = append(out, lib.Code...)
	out = append(out, lib.Infra...)
	out = append(out, lib.Chains...)
	return out
}

func defaultModels(in []string) []string {
	if len(in) == 0 {
		return []string{"anthropic:claude-opus-4-8"}
	}
	return in
}

func findBase() string {
	cwd, _ := os.Getwd()
	for dir := cwd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "agents_md")); err == nil {
			return dir
		}
	}
	return cwd
}

func addReconFlags(cmd *cobra.Command, reconFlag, fromRun, cachePath *string) {
	cmd.Flags().StringVar(reconFlag, "recon", "", "Recon policy: new, reuse, ask (default: ask on TTY, reuse off TTY)")
	cmd.Flags().StringVar(fromRun, "from-run", "", "Import recon from a prior run directory")
	cmd.Flags().StringVar(cachePath, "recon-cache", "", "Recon cache root (default: data/recon-cache)")
}

func applyReconFlags(cfg *types.RunConfig, reconFlag, fromRun, reconCache string) error {
	switch strings.ToLower(strings.TrimSpace(reconFlag)) {
	case "":
	case "new":
		cfg.ReconPolicy = types.ReconPolicyNew
	case "reuse":
		cfg.ReconPolicy = types.ReconPolicyReuse
	case "ask":
		cfg.ReconPolicy = types.ReconPolicyAsk
	default:
		return fmt.Errorf("invalid --recon %q (want new|reuse|ask)", reconFlag)
	}
	cfg.ReconFromRun = fromRun
	cfg.ReconCachePath = reconCache
	return nil
}

func runEngagement(ctx context.Context, cfg types.RunConfig, mcp bool, mode string, stub pipeline.PoolCaller) error {
	base := findBase()
	progress := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range progress {
			fmt.Println(line)
		}
	}()

	out, err := engagement.Execute(ctx, base, cfg, mode, mcp, stub, progress)
	close(progress)
	<-done

	if err != nil {
		return err
	}

	printFindings(out.Findings)
	if len(out.Artifacts) > 0 {
		fmt.Printf("artifacts: %s\n", strings.Join(out.Artifacts, ", "))
	}
	fmt.Printf("workdir: %s\n", out.Workdir)
	return nil
}

func printFindings(findings []types.Finding) {
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "Info"
		}
		fmt.Printf("[%s] %s — %s (%s)\n", sev, f.Title, f.Endpoint, f.CWE)
	}
}

type offlineStubPool struct{}

func (offlineStubPool) SetProgress(chan<- string) {}

func (offlineStubPool) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	ref := models.ModelRef{Provider: "offline", Model: "stub"}
	switch task {
	case pool.TaskRecon:
		return ref, `{}`, nil
	case pool.TaskSelect:
		return ref, `["sqli_error"]`, nil
	case pool.TaskExploit:
		return ref, `[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200 OK Server: nginx","payload":"'","confidence":0.9}]`, nil
	default:
		return ref, "{}", nil
	}
}

func (offlineStubPool) Vote(system, user string, n int, skip string) (int, int) {
	if n < 1 {
		n = 1
	}
	return n, n
}

func (offlineStubPool) StopExploiting() bool { return false }

func (offlineStubPool) Tools() *tools.Registry   { return nil }
func (offlineStubPool) Executor() tools.Executor { return nil }
func (offlineStubPool) Skills() *skills.Library  { return nil }
func (offlineStubPool) CompleteWithTools(label string, task pool.Task, system, user string, tools []map[string]any) (models.ModelRef, string, error) {
	return offlineStubPool{}.Complete(label, task, system, user)
}
