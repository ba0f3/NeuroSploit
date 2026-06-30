package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
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
			return cmd.Help()
		},
	}
	root.AddCommand(runCmd(), whiteboxCmd(), agentsCmd(), modelsCmd())
	return root
}

func runCmd() *cobra.Command {
	var modelsFlag []string
	var maxAgents, voteN int
	var offline, subscription, mcp bool
	var credsPath, focus string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "run <url>",
		Short: "Black-box recon → exploit → vote → report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := types.NewRunConfig(args[0])
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			if cfg.MaxAgents == 0 {
				cfg.MaxAgents = 5
			}
			cfg.VoteN = voteN
			cfg.Offline = offline
			cfg.Subscription = subscription
			cfg.Verbose = verbose
			if focus != "" {
				cfg.Instructions = &focus
			}
			cr := loadCreds(credsPath)
			applyCreds(&cfg, cr)
			if offline {
				// Stub pool simulates live pipeline without API keys; do not set cfg.Offline
				// (Rust offline skips exploitation; Go --offline is a self-test harness).
				cfg.Offline = false
				return runEngagement(cmd.Context(), cfg, cr, mcp, "run", offlineStubPool{})
			}
			return runEngagement(cmd.Context(), cfg, cr, mcp, "run", nil)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum agents to launch (0 = default 5)")
	cmd.Flags().IntVar(&voteN, "vote-n", 3, "Cross-model validation panel size")
	cmd.Flags().BoolVar(&offline, "offline", false, "Offline self-test using stubbed pool")
	cmd.Flags().BoolVar(&subscription, "subscription", false, "Use local agentic CLI subscriptions")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable Playwright MCP if available")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().StringVar(&focus, "focus", "", "Focus instructions")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	return cmd
}

func whiteboxCmd() *cobra.Command {
	var modelsFlag []string
	var maxAgents, voteN int
	var subscription, mcp, verbose bool
	var credsPath string

	cmd := &cobra.Command{
		Use:   "whitebox <path|url>",
		Short: "White-box source review of a local path or git repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := types.NewRunConfig(args[0])
			cfg.Models = defaultModels(modelsFlag)
			cfg.MaxAgents = maxAgents
			if cfg.MaxAgents == 0 {
				cfg.MaxAgents = 3
			}
			cfg.VoteN = voteN
			cfg.Subscription = subscription
			cfg.Verbose = verbose
			cr := loadCreds(credsPath)
			applyCreds(&cfg, cr)
			return runEngagement(cmd.Context(), cfg, cr, mcp, "whitebox", nil)
		},
	}
	cmd.Flags().StringArrayVar(&modelsFlag, "model", []string{"anthropic:claude-opus-4-8"}, "Models as provider:model")
	cmd.Flags().IntVar(&maxAgents, "max-agents", 0, "Maximum agents")
	cmd.Flags().IntVar(&voteN, "vote-n", 2, "Cross-model validation panel size")
	cmd.Flags().BoolVar(&subscription, "subscription", false, "Use local CLI subscriptions")
	cmd.Flags().BoolVar(&mcp, "mcp", false, "Enable MCP")
	cmd.Flags().StringVar(&credsPath, "creds", "", "Path to creds.yaml")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	return cmd
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

func loadCreds(path string) *creds.Creds {
	if path == "" {
		return nil
	}
	return creds.Load(path)
}

func applyCreds(cfg *types.RunConfig, cr *creds.Creds) {
	if cr == nil {
		return
	}
	if h := cr.AuthHeader(); h != nil {
		cfg.Auth = h
	}
}

func buildPool(cfg types.RunConfig, mcp bool, workdir string) *pool.ModelPool {
	var refs []models.ModelRef
	for _, s := range cfg.Models {
		refs = append(refs, models.ModelRefParse(s))
	}
	mcpConfig := ""
	if mcp && cfg.Subscription && len(refs) > 0 && models.MCPSupported(refs[0].Provider) {
		_ = models.EnsurePlaywrightMCP()
		mcpConfig, _ = models.WriteMCPConfig(workdir, "")
	}
	p := pool.WithAuth(refs, cfg.Concurrency, cfg.Subscription, mcpConfig)
	p.Client = models.NewChatClient()
	return p
}

func runEngagement(ctx context.Context, cfg types.RunConfig, cr *creds.Creds, mcp bool, mode string, stub pipeline.PoolCaller) error {
	base := findBase()
	lib := agents.Load(base)

	workdir := filepath.Join("runs", fmt.Sprintf("ns-%d-%s", time.Now().Unix(), sanitizeTarget(cfg.Target)))
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return err
	}
	cfg.Workdir = &workdir
	rlPath := filepath.Join(base, "data", "rl_state_go.json")
	cfg.RLPath = &rlPath
	_ = os.MkdirAll(filepath.Dir(rlPath), 0755)

	var p pipeline.PoolCaller
	if stub != nil {
		p = stub
	} else {
		p = buildPool(cfg, mcp, workdir)
	}

	progress := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range progress {
			fmt.Println(line)
		}
	}()

	var out pipeline.RunOutput
	switch mode {
	case "whitebox":
		out = pipeline.RunWhitebox(ctx, cfg, lib, p, progress)
	default:
		out = pipeline.Run(ctx, cfg, lib, p, progress)
	}
	close(progress)
	<-done

	_ = cr // creds applied via cfg.Auth in pipeline operator directives
	printFindings(out.Findings)
	if len(out.Artifacts) > 0 {
		fmt.Printf("artifacts: %s\n", strings.Join(out.Artifacts, ", "))
	}
	fmt.Printf("workdir: %s\n", out.Workdir)
	return nil
}

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeTarget(target string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	s = sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		return "target"
	}
	return s
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
