package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/attackgraph"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/grounding"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/hygiene"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pomdp"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/registry"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Runner orchestrates the reconnaissance-exploitation-validation loop.
type Runner struct {
	Pool     PoolClient
	Registry *registry.Registry
	World    *belief.WorldModel
	Policy   pomdp.Policy
	Creds    *creds.Creds
}

// PoolClient is the subset of pool.ModelPool used by the pipeline (testable interface).
type PoolClient interface {
	Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error)
	Vote(system, user string, n int, skip string) (int, int)
	IsCancelled() bool
	IsStopped() bool
}

// New creates a Runner.
func New(p PoolClient, reg *registry.Registry, wm *belief.WorldModel, cr *creds.Creds) *Runner {
	if wm == nil {
		wm = &belief.WorldModel{Nodes: map[string]belief.Node{}}
	}
	return &Runner{
		Pool:     p,
		Registry: reg,
		World:    wm,
		Policy:   pomdp.DefaultPolicy(),
		Creds:    cr,
	}
}

// Run executes the engagement loop until the policy says stop or the context is cancelled.
func (r *Runner) Run(ctx context.Context, cfg types.RunConfig) error {
	if r.Pool == nil {
		return fmt.Errorf("no model pool configured")
	}
	r.World.Add("target", belief.KindHost, cfg.Target, 1.0)

	for i := 0; i < cfg.MaxAgents; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if r.Pool.IsCancelled() || r.Pool.IsStopped() {
			break
		}
		action := pomdp.Decide(r.World, r.Policy)
		if action.Type == "stop" {
			break
		}
		if action.Type == "exploit" {
			if err := r.exploit(ctx, cfg, action.Node); err != nil {
				return err
			}
		} else if action.Type == "recon" {
			if err := r.recon(ctx, cfg, action.Node); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) recon(ctx context.Context, cfg types.RunConfig, nodeID string) error {
	_, text, err := r.Pool.Complete("recon", pool.TaskRecon, reconSystem(), cfg.Target)
	if err != nil {
		return err
	}
	// Recon makes the target more known.
	r.World.Observe("target", true, 0.7)
	_ = text
	return nil
}

func (r *Runner) exploit(ctx context.Context, cfg types.RunConfig, nodeID string) error {
	if err := pomdp.MayAssert(r.World, nodeID, r.Policy); err != nil {
		return fmt.Errorf("anti-hallucination gate: %w", err)
	}
	system := exploitSystem(cfg.Target)
	if r.Creds != nil {
		if auth := r.Creds.AuthHeader(); auth != nil {
			system += "\nAuth header: " + *auth
		}
	}
	m, text, err := r.Pool.Complete("exploit", pool.TaskExploit, system, cfg.Target)
	if err != nil {
		return err
	}
	findings := parseFindings(text, m.Label())
	for i := range findings {
		f := &findings[i]
		if res := grounding.Ground(f, text, false); !res.OK {
			f.Validated = false
			f.Votes = f.Votes + " receipt_missing"
			continue
		}
		findingsSlice := []types.Finding{*f}
		hygiene.Calibrate(&findingsSlice)
		attackgraph.Enrich(&findingsSlice)
		*f = findingsSlice[0]
		if f.Severity == "" {
			f.Severity = "Info"
		}
		if r.Registry != nil {
			_ = r.Registry.Append(*f, true)
		}
	}
	return nil
}

// Validate runs a cross-model vote on a finding.
func (r *Runner) Validate(ctx context.Context, f types.Finding) (bool, error) {
	if r.Pool == nil {
		return false, fmt.Errorf("no model pool configured")
	}
	confirmed, total := r.Pool.Vote(validateSystem(f), "", 3, f.Agent)
	if total == 0 {
		return false, nil
	}
	return confirmed >= total/2+1, nil
}

// Findings returns all findings from the registry.
func (r *Runner) Findings() []types.Finding {
	if r.Registry == nil {
		return nil
	}
	return r.Registry.Findings()
}

func parseFindings(text, agent string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "CWE-") || strings.Contains(line, "finding:") {
			findings = append(findings, types.Finding{
				ID:       fmt.Sprintf("%s-%d", agent, len(findings)+1),
				Agent:    agent,
				Title:    line,
				Evidence: text,
			})
		}
	}
	return findings
}

func reconSystem() string {
	return `You are a reconnaissance agent. Enumerate the target. Return concise bullet points. Do not exploit.`
}

func exploitSystem(target string) string {
	return fmt.Sprintf(`You are a security tester authorized to test %s. Identify vulnerabilities and report them with CWE references, severity, and evidence. Do not run destructive commands.`, target)
}

func validateSystem(f types.Finding) string {
	return fmt.Sprintf(`Review the following finding and respond with only "yes" if it is a real, confirmed vulnerability, or "no" otherwise.
Title: %s
Evidence: %s
CWE: %s`, f.Title, f.Evidence, f.CWE)
}
