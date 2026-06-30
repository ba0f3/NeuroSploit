package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/registry"
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
			if focus != "" {
				cfg.Instructions = &focus
			}

			var cr *creds.Creds
			if credsPath != "" {
				cr = creds.Load(credsPath)
			}

			if cfg.Offline {
				return offlineRun(cmd.Context(), cfg, cr, verbose)
			}
			return realRun(cmd.Context(), cfg, cr, mcp, verbose)
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

			var cr *creds.Creds
			if credsPath != "" {
				cr = creds.Load(credsPath)
			}
			fmt.Println("whitebox review:", args[0])
			return realRun(cmd.Context(), cfg, cr, mcp, verbose)
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
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "agents_md")); err == nil {
				return dir
			}
		}
	}
	return cwd
}

func realRun(ctx context.Context, cfg types.RunConfig, cr *creds.Creds, mcp, verbose bool) error {
	var refs []models.ModelRef
	for _, s := range cfg.Models {
		refs = append(refs, models.ModelRefParse(s))
	}
	p := pool.New(refs, cfg.Concurrency)
	p.Subscription = cfg.Subscription

	if mcp && cfg.Subscription {
		if models.MCPSupported(refs[0].Provider) {
			if cfg.Workdir != nil && *cfg.Workdir != "" {
				_ = models.EnsurePlaywrightMCP()
				p.MCPConfig, _ = models.WriteMCPConfig(*cfg.Workdir, "")
			}
		}
	}

	workdir := "."
	if cfg.Workdir != nil {
		workdir = *cfg.Workdir
	}
	reg := registry.New(filepath.Join(workdir, "findings.jsonl"))
	wm := &belief.WorldModel{Nodes: map[string]belief.Node{}}
	r := pipeline.New(p, reg, wm, cr)
	if err := r.Run(ctx, cfg); err != nil {
		return err
	}
	findings := r.Findings()
	if verbose {
		fmt.Printf("findings: %d\n", len(findings))
	}
	printFindings(findings)
	return nil
}

func offlineRun(ctx context.Context, cfg types.RunConfig, cr *creds.Creds, verbose bool) error {
	stub := &stubPool{}
	reg := registry.New(filepath.Join(".", "findings.jsonl"))
	wm := &belief.WorldModel{Nodes: map[string]belief.Node{}}
	wm.Add("xss", belief.KindVuln, "reflected xss", 0.95)
	r := pipeline.New(stub, reg, wm, cr)
	if err := r.Run(ctx, cfg); err != nil {
		return err
	}
	findings := r.Findings()
	if verbose {
		fmt.Printf("offline findings: %d\n", len(findings))
	}
	printFindings(findings)
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

type stubPool struct{}

func (stubPool) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	return models.ModelRef{Provider: "offline", Model: "stub"}, `HTTP/1.1 200 OK
finding: Offline Test CWE-79 on ` + user, nil
}

func (stubPool) Vote(system, user string, n int, skip string) (int, int) {
	return 1, 1
}

func (stubPool) IsCancelled() bool { return false }
func (stubPool) IsStopped() bool   { return false }
