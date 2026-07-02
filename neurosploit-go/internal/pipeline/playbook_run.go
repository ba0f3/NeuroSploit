package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/playbooks"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/rl"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// RunPlaybook executes a named playbook instead of the default pipeline.
func RunPlaybook(ctx context.Context, cfg types.RunConfig, lib agents.Library, p PoolCaller, pb playbooks.Playbook, progress chan<- string) RunOutput {
	p.SetProgress(progress)
	sendProgress(progress, fmt.Sprintf("PLAYBOOK · %s — %s · loaded %d agents%s · models: %s",
		pb.Name, pb.Description, lib.Total(), loadedToolsSkills(p), poolModelLabels(p)))

	vars := map[string]string{"target": cfg.Target}
	engine := &playbooks.Engine{
		ToolRegistry: p.Tools(),
		Executor:     p.Executor(),
		SkillLibrary: p.Skills(),
		Progress:     progress,
		AgentRunner: func(ctx context.Context, name string, state map[string]any) ([]types.Finding, error) {
			ag, ok := findAgent(lib, name)
			if !ok {
				return nil, fmt.Errorf("agent %s not found", name)
			}
			recon := "{}"
			if v, ok := state["recon"].(string); ok {
				recon = v
			}
			mcpOn := mcpEnabled(p)
			builder := exploitUserBuilder{target: cfg.Target, directives: operatorDirectives(cfg), mcpOn: mcpOn}
			system := injectSkills(p, ag, ag.System, cfg)
			user := builder.build(ag, recon)
			var text string
			var err error
			if (cfg.AutoTools || len(ag.Tools) > 0) && p.Tools() != nil && p.Executor() != nil {
				toolList := selectTools(p.Tools(), "exploit", ag.Tools)
				text, _, err = runWithToolLoop(ctx, p, name, pool.TaskExploit, system, user, toolList, progress)
			} else {
				_, text, err = p.Complete(name, pool.TaskExploit, system, user)
			}
			if err != nil {
				return nil, err
			}
			return extractFindings(text, name), nil
		},
	}

	state, candidates, err := engine.Run(ctx, pb, vars)
	if err != nil {
		sendProgress(progress, fmt.Sprintf("playbook error: %v", err))
		return RunOutput{Target: cfg.Target}
	}
	recon := "{}"
	if v, ok := state["tool_httpx"]; ok {
		recon = fmt.Sprintf("%v", v)
	}
	sendProgress(progress, fmt.Sprintf("playbook produced %d candidate finding(s) — validating", len(candidates)))
	findings := validate(dedupFindings(candidates), p, voteSys, cfg.VoteN, progress)
	chained := runChainEngine(ctx, cfg, p, recon, findings, lib.Chains, progress, mcpEnabled(p))
	findings = append(findings, chained...)
	findings = dedupFindings(findings)
	findings = refutePass(findings, p, cfg.VoteN, progress)
	var rlState rl.State
	if cfg.RLPath != nil {
		rlState = rl.Load(*cfg.RLPath)
	}
	_ = state
	return finish(cfg, recon, "", "", findings, nil, &rlState, progress)
}

func findAgent(lib agents.Library, name string) (agents.Agent, bool) {
	for _, lists := range [][]agents.Agent{lib.Vulns, lib.Recon, lib.Infra, lib.Code, lib.Meta, lib.Chains} {
		for _, a := range lists {
			if a.Name == name || strings.EqualFold(a.Name, name) {
				return a, true
			}
		}
	}
	return agents.Agent{}, false
}
