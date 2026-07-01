package chainengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Caller runs one chain-stage LLM turn.
type Caller interface {
	RunStage(ctx context.Context, agent agents.Agent, user string) (string, error)
}

// ParseFindings extracts findings from model output text.
type ParseFindings func(text, agent string) []types.Finding

// Config drives a chain run.
type Config struct {
	Target      string
	Recon       string
	Directives  string
	Confirmed   []types.Finding
	Chains      []agents.Agent
	ChainSystem string
	Doctrine    string // react + depth + tool blocks prepended to user prompt
}

// Engine runs chain agents sequentially with precondition checks and early stop.
type Engine struct {
	Caller        Caller
	ParseFindings ParseFindings
	Progress      chan<- string
}

// Run executes matching chain stages; stops when a stage yields no provable findings.
func (e *Engine) Run(ctx context.Context, cfg Config) []types.Finding {
	if len(cfg.Confirmed) == 0 || len(cfg.Chains) == 0 || e.Caller == nil {
		return nil
	}
	var summary strings.Builder
	for i, f := range cfg.Confirmed {
		if i >= 20 {
			break
		}
		fmt.Fprintf(&summary, "- [%s] %s @ %s (%s)\n", f.Severity, f.Title, f.Endpoint, f.CWE)
	}
	reconCtx := cfg.Recon
	if len([]rune(reconCtx)) > 2500 {
		reconCtx = string([]rune(reconCtx)[:2500])
	}

	var out []types.Finding
	for _, ag := range cfg.Chains {
		if !preconditionsMatch(ag.Preconditions, cfg.Confirmed) {
			e.emit(fmt.Sprintf("chain %s skipped (preconditions not met)", ag.Name))
			continue
		}
		e.emit(fmt.Sprintf("chain stage %s start", ag.Name))
		user := fmt.Sprintf(
			"AUTHORIZED engagement on %s.\n\n%s%sCONFIRMED FINDINGS TO CHAIN:\n%s\n\nRecon:\n%s\n\n"+
				"Advance this chain stage by stage and PROVE each step with raw tool output. "+
				"Reply ONLY a JSON array of NEW findings (may be []): {id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}.",
			cfg.Target, cfg.Directives+cfg.Doctrine, chainRecipeBlock(ag), summary.String(), reconCtx,
		)
		text, err := e.Caller.RunStage(ctx, ag, user)
		if err != nil {
			e.emit(fmt.Sprintf("chain %s failed: %v — stopping", ag.Name, err))
			break
		}
		var findings []types.Finding
		if e.ParseFindings != nil {
			findings = e.ParseFindings(text, ag.Name)
		}
		if len(findings) == 0 {
			e.emit(fmt.Sprintf("chain %s: no provable findings — stopping early", ag.Name))
			break
		}
		e.emit(fmt.Sprintf("chain %s → %d new candidate(s)", ag.Name, len(findings)))
		out = append(out, findings...)
	}
	return out
}

func chainRecipeBlock(ag agents.Agent) string {
	title := strings.ReplaceAll(ag.Title, " Agent", "")
	return fmt.Sprintf("CHAIN RECIPE: %s\n\n", title)
}

func preconditionsMatch(preconds []string, confirmed []types.Finding) bool {
	if len(preconds) == 0 {
		return true
	}
	for _, pre := range preconds {
		pre = strings.ToLower(strings.TrimSpace(pre))
		if pre == "" {
			continue
		}
		for _, f := range confirmed {
			hay := strings.ToLower(f.Title + " " + f.CWE + " " + f.Endpoint + " " + f.Agent)
			if strings.Contains(hay, pre) {
				return true
			}
		}
	}
	return false
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
