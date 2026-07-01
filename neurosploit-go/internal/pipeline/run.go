package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/attackgraph"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/chainengine"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/grounding"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/hygiene"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/rl"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/toolloop"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"golang.org/x/sync/errgroup"
)

// RunOutput is the result of an engagement run.
type RunOutput struct {
	Target     string          `json:"target"`
	Findings   []types.Finding `json:"findings"`
	AgentsRan  []string        `json:"agents_ran"`
	Candidates int             `json:"candidates"`
	Recon      string          `json:"recon"`
	Workdir    string          `json:"workdir"`
	Artifacts  []string        `json:"artifacts"`
}

// PoolCaller is the subset of pool.ModelPool used by the pipeline (testable interface).
type PoolCaller interface {
	SetProgress(chan<- string)
	Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error)
	CompleteWithTools(label string, task pool.Task, system, user string, tools []map[string]any) (models.ModelRef, string, error)
	Vote(system, user string, n int, skip string) (confirmed, total int)
	StopExploiting() bool
	Tools() *tools.Registry
	Executor() tools.Executor
	Skills() *skills.Library
}

type exploitResult struct {
	name     string
	text     string
	findings []types.Finding
}

// Run executes the black-box web engagement pipeline.
func Run(ctx context.Context, cfg types.RunConfig, lib agents.Library, p PoolCaller, progress chan<- string) RunOutput {
	p.SetProgress(progress)
	mcpOn := mcpEnabled(p)
	sendProgress(progress, fmt.Sprintf(
		"Loaded %d agents (%d vuln / %d recon / %d code / %d meta)%s · models: %s · vote_n=%d · concurrency=%d%s",
		lib.Total(), len(lib.Vulns), len(lib.Recon), len(lib.Code), len(lib.Meta),
		loadedToolsSkills(p),
		poolModelLabels(p), cfg.VoteN, cfg.Concurrency, mcpSuffix(mcpOn),
	))

	recon, toolLog := runRecon(ctx, cfg, p, progress, mcpOn)

	var rlState rl.State
	if cfg.RLPath != nil {
		rlState = rl.Load(*cfg.RLPath)
	}
	ranked := rankAgents(lib.Vulns, rlState)
	cap := agentCap(len(ranked), cfg.MaxAgents)

	if cfg.Offline {
		selected := takeAgents(ranked, cap)
		sendProgress(progress, fmt.Sprintf("selected %d specialist agents (RL-ranked)", len(selected)))
		sendProgress(progress, "offline: no exploitation performed (provide API keys or --subscription to run live)")
		artifacts := persist(cfg, recon, "", toolLog, nil)
		return buildOutput(cfg, recon, nil, selected, 0, artifacts)
	}

	focus := ""
	if cfg.Instructions != nil {
		focus = *cfg.Instructions
	}
	chosen := selectAgents(p, recon, focus, ranked, progress)
	selected := pickSelectedByName(ranked, chosen, recon, focus, cap, progress)
	selected = dedupAgentList(selected)
	sendProgress(progress, fmt.Sprintf("intelligently selected %d agent(s) matching recon: %s",
		len(selected), agentNames(selected)))

	raw := parallelExploit(ctx, cfg, selected, p, progress, recon, mcpOn, exploitUserBuilder{
		target:     cfg.Target,
		directives: operatorDirectives(cfg),
		mcpOn:      mcpOn,
	})

	transcript := transcriptOf(raw)
	candidates := dedupFindings(flattenFindings(raw))
	sendProgress(progress, fmt.Sprintf("%d candidate finding(s) (deduped) — validating by %d-model vote", len(candidates), cfg.VoteN))

	findings := validate(candidates, p, voteSys, cfg.VoteN, progress)
	chained := runChainEngine(ctx, cfg, p, recon, findings, lib.Chains, progress, mcpOn)
	if len(chained) > 0 {
		extra := validate(dedupFindings(chained), p, voteSys, cfg.VoteN, progress)
		sendProgress(progress, fmt.Sprintf("chaining added %d validated finding(s)", len(extra)))
		findings = append(findings, extra...)
		findings = dedupFindings(findings)
	}
	return finish(cfg, recon, transcript, toolLog, findings, selected, &rlState, progress)
}

func selectTools(reg *tools.Registry, mode string, requested []string) []tools.Tool {
	if reg == nil {
		return nil
	}
	var out []tools.Tool
	if len(requested) > 0 {
		for _, name := range requested {
			if t, ok := reg.Get(name); ok {
				out = append(out, t)
			}
		}
		return out
	}
	defaults := map[string][]string{
		"recon": {"httpx", "whatweb", "katana", "nmap", "nuclei", "gau", "subfinder"},
		"host":  {"nmap", "rustscan", "naabu"},
	}
	for _, name := range defaults[mode] {
		if t, ok := reg.Get(name); ok {
			out = append(out, t)
		}
	}
	return out
}

func injectSkills(p PoolCaller, ag agents.Agent, system string, cfg types.RunConfig) string {
	names := ag.Skills
	if cfg.AutoSkills && len(cfg.Skills) > 0 {
		names = append(names, cfg.Skills...)
	}
	if p.Skills() == nil || len(names) == 0 {
		return system
	}
	seen := make(map[string]bool)
	var blocks []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if s, ok := p.Skills().Get(name); ok {
			blocks = append(blocks, s.PromptBlock())
		}
	}
	if len(blocks) == 0 {
		return system
	}
	return system + "\n\n" + strings.Join(blocks, "\n\n")
}

func runWithToolLoop(ctx context.Context, p PoolCaller, label string, task pool.Task, system, user string, toolList []tools.Tool, progress chan<- string) (string, []toolloop.Observation, error) {
	if len(toolList) == 0 || p.Executor() == nil {
		_, text, err := p.Complete(label, task, system, user)
		return text, nil, err
	}
	caller := toolloop.CallerFunc(func(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error) {
		_, text, err := p.CompleteWithTools(label, task, system, user, toolsJSON)
		return text, err
	})
	loop := &toolloop.Loop{
		Caller:   caller,
		Executor: p.Executor(),
		MaxIter:  10,
		Progress: progress,
	}
	sendProgress(progress, fmt.Sprintf("toolloop enabled for %s with tools: %s", label, toolNames(toolList)))
	return loop.Run(ctx, system, user, toolList)
}

func toolNames(list []tools.Tool) string {
	var names []string
	for _, t := range list {
		names = append(names, t.Name)
	}
	return strings.Join(names, ", ")
}

func runRecon(ctx context.Context, cfg types.RunConfig, p PoolCaller, progress chan<- string, mcpOn bool) (string, string) {
	if cfg.Offline {
		sendProgress(progress, "recon: offline mode — skipping model calls")
		return "{}", ""
	}
	select {
	case <-ctx.Done():
		return "{}", ""
	default:
	}
	reconUser := fmt.Sprintf("%s%sTarget: %s", operatorDirectives(cfg), toolDoctrine(mcpOn), cfg.Target)
	var m models.ModelRef
	var text string
	var toolLog string
	var err error
	if p.Tools() != nil && p.Executor() != nil {
		var obs []toolloop.Observation
		toolList := selectTools(p.Tools(), "recon", nil)
		text, obs, err = runWithToolLoop(ctx, p, "recon", pool.TaskRecon, reconSys, reconUser, toolList, progress)
		toolLog = formatToolLog(obs)
		text = finalizeReconText(text)
	} else {
		m, text, err = p.Complete("recon", pool.TaskRecon, reconSys, reconUser)
		text = finalizeReconText(text)
	}
	if err != nil {
		sendProgress(progress, fmt.Sprintf("recon failed (%v) — continuing with empty recon", err))
		return "{}", toolLog
	}
	if m.Label() != "" {
		sendProgress(progress, fmt.Sprintf("recon complete via %s", m.Label()))
	} else {
		sendProgress(progress, "recon complete")
	}
	if cfg.Verbose {
		snip := stripCodeFences(text)
		if len([]rune(snip)) > 280 {
			snip = string([]rune(snip)[:280])
		}
		sendProgress(progress, fmt.Sprintf("  recon> %s", strings.ReplaceAll(snip, "\n", " ")))
	}
	return text, toolLog
}

type exploitUserBuilder struct {
	target     string
	directives string
	mcpOn      bool
	leads      string
	greybox    bool
	host       bool
}

func (b exploitUserBuilder) build(ag agents.Agent, recon string) string {
	body := agents.RenderPrompt(ag.User, map[string]string{
		"target":     b.target,
		"recon_json": recon,
	})
	if b.host {
		return fmt.Sprintf(
			"AUTHORIZED host engagement on %s. Proceed and PROVE each issue with raw tool output.\n\n%s%s%s%s%s%s\n\n%s",
			b.target, b.directives, hostTooling, reactDoctrine, evidenceDoctrine, severityDoctrine, body, outputSchemaDoctrine,
		)
	}
	if b.greybox {
		return fmt.Sprintf(
			"AUTHORIZED greybox engagement on %s — you also have the source review below. Proceed and PROVE each issue against the LIVE app.\n\n%s%s%s%s%s%s%s\n\n%s",
			b.target, b.directives, b.leads, reactDoctrine, depthDoctrine, evidenceDoctrine, toolDoctrine(b.mcpOn), body, outputSchemaDoctrine,
		)
	}
	return fmt.Sprintf(
		"AUTHORIZED engagement — you have explicit permission to test %s. Do not ask for confirmation — proceed and PROVE each issue.\n\n%s%s%s%s%s%s%s\n\n%s",
		b.target, b.directives, reactDoctrine, depthDoctrine, evidenceDoctrine, severityDoctrine, toolDoctrine(b.mcpOn), body, outputSchemaDoctrine,
	)
}

func parallelExploit(ctx context.Context, cfg types.RunConfig, selected []agents.Agent, p PoolCaller, progress chan<- string, recon string, mcpOn bool, builder exploitUserBuilder) []exploitResult {
	reconCtx := recon
	if len([]rune(reconCtx)) > 3500 {
		reconCtx = string([]rune(reconCtx)[:3500])
	}
	results := make([]exploitResult, len(selected))
	g, gctx := errgroup.WithContext(ctx)
	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	g.SetLimit(limit)
	for i, ag := range selected {
		i, ag := i, ag
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}
			if p.StopExploiting() {
				results[i] = exploitResult{name: ag.Name}
				return nil
			}
			if cfg.Verbose {
				sendProgress(progress, fmt.Sprintf("  ▶ launching agent: %s (%s)", ag.Name, strings.ReplaceAll(ag.Title, " Agent", "")))
			}
			user := builder.build(ag, reconCtx)
			system := injectSkills(p, ag, ag.System, cfg)
			if ag.OutputSchema != "" {
				system = system + "\n\n" + agentOutputSchema(ag)
			}
			var m models.ModelRef
			var text string
			var err error
			if (cfg.AutoTools || len(ag.Tools) > 0) && p.Tools() != nil && p.Executor() != nil {
				toolList := selectTools(p.Tools(), "exploit", ag.Tools)
				text, _, err = runWithToolLoop(ctx, p, ag.Name, pool.TaskExploit, system, user, toolList, progress)
			} else {
				m, text, err = p.Complete(ag.Name, pool.TaskExploit, system, user)
			}
			verb := "exploit"
			if builder.host {
				verb = "test"
			}
			if err != nil {
				sendProgress(progress, fmt.Sprintf("%s %s failed: %v", verb, ag.Name, err))
				results[i] = exploitResult{name: ag.Name, text: fmt.Sprintf("ERROR: %v", err)}
				return nil
			}
			f := extractFindings(text, ag.Name)
			sendProgress(progress, fmt.Sprintf("%s %s via %s → %d candidate(s)", verb, ag.Name, m.Label(), len(f)))
			for _, c := range f {
				sendProgress(progress, fmt.Sprintf("finding: [%s] %s @ %s", c.Severity, c.Title, c.Endpoint))
				if b, err := json.Marshal(c); err == nil {
					sendProgress(progress, "finding_json: "+string(b))
				}
			}
			results[i] = exploitResult{name: ag.Name, text: text, findings: f}
			return nil
		})
	}
	_ = g.Wait()
	return results
}

func runChainEngine(ctx context.Context, cfg types.RunConfig, p PoolCaller, recon string, confirmed []types.Finding, chains []agents.Agent, progress chan<- string, mcpOn bool) []types.Finding {
	if len(confirmed) == 0 {
		return nil
	}
	sendProgress(progress, fmt.Sprintf("chaining %d confirmed finding(s) for deeper impact…", len(confirmed)))
	doctrine := reactDoctrine + depthDoctrine + toolDoctrine(mcpOn)
	engine := &chainengine.Engine{
		Caller: &chainStageCaller{pool: p, cfg: cfg, mcpOn: mcpOn},
		ParseFindings: func(text, agent string) []types.Finding {
			return extractFindings(text, agent)
		},
		Progress: progress,
	}
	return engine.Run(ctx, chainengine.Config{
		Target:      cfg.Target,
		Recon:       recon,
		Directives:  operatorDirectives(cfg),
		Confirmed:   confirmed,
		Chains:      chains,
		ChainSystem: chainSys,
		Doctrine:    doctrine,
	})
}

type chainStageCaller struct {
	pool  PoolCaller
	cfg   types.RunConfig
	mcpOn bool
}

func (c *chainStageCaller) RunStage(ctx context.Context, ag agents.Agent, user string) (string, error) {
	system := injectSkills(c.pool, ag, chainSys, c.cfg)
	if (c.cfg.AutoTools || len(ag.Tools) > 0) && c.pool.Tools() != nil && c.pool.Executor() != nil {
		toolList := selectTools(c.pool.Tools(), "exploit", ag.Tools)
		text, _, err := runWithToolLoop(ctx, c.pool, "chain:"+ag.Name, pool.TaskExploit, system, user, toolList, nil)
		return text, err
	}
	_, text, err := c.pool.Complete("chain:"+ag.Name, pool.TaskExploit, system, user)
	return text, err
}

func validate(candidates []types.Finding, p PoolCaller, sys string, voteN int, progress chan<- string) []types.Finding {
	finder := primaryModelLabel(p)
	concurrency := validateConcurrency(p)
	sem := make(chan struct{}, concurrency)
	validated := make([]types.Finding, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(i int, f types.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			q := fmt.Sprintf("Finding: %s | severity %s | %s | at %s | payload %s | evidence %s",
				f.Title, f.Severity, f.CWE, f.Endpoint, f.Payload, f.Evidence)
			yes, total := p.Vote(sys, q, voteN, finder)
			f.Validated = total > 0 && yes*2 >= total
			f.Votes = fmt.Sprintf("%d/%d", yes, total)
			if f.Confidence == 0 && total > 0 {
				f.Confidence = float64(yes) / float64(total)
			}
			verdict := "rejected"
			if f.Validated {
				verdict = "CONFIRMED"
			}
			sendProgress(progress, fmt.Sprintf("vote %s → %s (%s)", f.Title, verdict, f.Votes))
			validated[i] = f
		}(i, c)
	}
	wg.Wait()
	var out []types.Finding
	for _, f := range validated {
		if f.Validated {
			out = append(out, f)
		}
	}
	return out
}

func finish(cfg types.RunConfig, recon, transcript, toolLog string, findings []types.Finding, selected []agents.Agent, rlState *rl.State, progress chan<- string) RunOutput {
	whitebox := cfg.Repo != nil && strings.HasPrefix(cfg.Target, "/")
	before := len(findings)
	kept, demoted := grounding.Gate(findings, transcript, whitebox)
	findings = kept
	if demoted > 0 {
		sendProgress(progress, fmt.Sprintf("grounding gate: demoted %d/%d ungrounded claim(s) (no tool receipt)", demoted, before))
	}
	for _, n := range hygiene.Calibrate(&findings) {
		sendProgress(progress, fmt.Sprintf("calibrate: %s", n))
	}
	for _, n := range hygiene.DepthAudit(findings) {
		sendProgress(progress, fmt.Sprintf("notify: %s", n))
	}
	for _, n := range hygiene.HygieneSummary(findings) {
		sendProgress(progress, fmt.Sprintf("notify: %s", n))
	}

	wm := &belief.WorldModel{Nodes: map[string]belief.Node{}, Deterministic: whitebox}
	for _, f := range findings {
		conf := f.Confidence
		if conf < 0.05 {
			conf = 0.05
		}
		if conf > 0.99 {
			conf = 0.99
		}
		wm.Add(f.ID, belief.KindExploit, f.Title, conf)
	}
	if len(findings) > 0 {
		sendProgress(progress, fmt.Sprintf("belief uncertainty over confirmed findings: %.2f (0=sharp,1=diffuse)", wm.Uncertainty(belief.KindNone)))
	}

	sendProgress(progress, fmt.Sprintf("%d validated finding(s)", len(findings)))
	attackgraph.Enrich(&findings)

	hit := map[string]float64{}
	for _, f := range findings {
		v := hit[f.Agent] + rl.SeverityReward(f.Severity)
		if v > 1.0 {
			v = 1.0
		}
		hit[f.Agent] = v
	}
	for _, a := range selected {
		r := hit[a.Name]
		if r == 0 {
			r = -0.05
		}
		rlState.Update(a.Name, r)
	}
	rlState.Runs++
	if cfg.RLPath != nil {
		if err := rlState.Save(*cfg.RLPath); err == nil {
			sendProgress(progress, "RL rewards updated")
		}
	}

	artifacts := persist(cfg, recon, transcript, toolLog, findings)
	if len(artifacts) > 0 {
		wd := ""
		if cfg.Workdir != nil {
			wd = *cfg.Workdir
		}
		sendProgress(progress, fmt.Sprintf("notify: evidence saved → %s", wd))
		sendProgress(progress, fmt.Sprintf("artifacts saved: %s", strings.Join(artifacts, ", ")))
	}
	bySev := map[string]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	sev := "none"
	if len(bySev) > 0 {
		keys := make([]string, 0, len(bySev))
		for k := range bySev {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s:%d", k, bySev[k]))
		}
		sev = strings.Join(parts, " ")
	}
	sendProgress(progress, fmt.Sprintf("notify: phase complete — %d validated finding(s) [%s]", len(findings), sev))

	return buildOutput(cfg, recon, findings, selected, len(findings), artifacts)
}

func buildOutput(cfg types.RunConfig, recon string, findings []types.Finding, selected []agents.Agent, candidates int, artifacts []string) RunOutput {
	wd := ""
	if cfg.Workdir != nil {
		wd = *cfg.Workdir
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	return RunOutput{
		Target:     cfg.Target,
		Workdir:    wd,
		Candidates: candidates,
		Findings:   findings,
		AgentsRan:  agentNames(selected),
		Recon:      recon,
		Artifacts:  artifacts,
	}
}

func rankAgents(vulns []agents.Agent, state rl.State) []agents.Agent {
	ranked := append([]agents.Agent(nil), vulns...)
	sort.Slice(ranked, func(i, j int) bool {
		return state.Weight(ranked[i].Name) > state.Weight(ranked[j].Name)
	})
	return ranked
}

func agentCap(total, maxAgents int) int {
	if maxAgents > 0 && maxAgents < total {
		return maxAgents
	}
	return total
}

func takeAgents(ranked []agents.Agent, cap int) []agents.Agent {
	if cap >= len(ranked) {
		return append([]agents.Agent(nil), ranked...)
	}
	return append([]agents.Agent(nil), ranked[:cap]...)
}

func pickSelectedByName(ranked []agents.Agent, names []string, recon, focus string, cap int, progress chan<- string) []agents.Agent {
	if len(names) == 0 {
		return heuristicSelect(ranked, recon, focus, cap)
	}
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	var sel []agents.Agent
	for _, a := range ranked {
		if nameSet[a.Name] {
			sel = append(sel, a)
		}
	}
	if len(sel) == 0 {
		sendProgress(progress, "selection empty — using recon-keyword heuristic")
		return heuristicSelect(ranked, recon, focus, cap)
	}
	return takeAgents(sel, cap)
}

func dedupAgentList(agentList []agents.Agent) []agents.Agent {
	seen := make(map[string]bool)
	var out []agents.Agent
	for _, a := range agentList {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		out = append(out, a)
	}
	return out
}

func agentNames(agentList []agents.Agent) []string {
	names := make([]string, len(agentList))
	for i, a := range agentList {
		names[i] = a.Name
	}
	return names
}

func flattenFindings(raw []exploitResult) []types.Finding {
	var out []types.Finding
	for _, r := range raw {
		out = append(out, r.findings...)
	}
	return out
}

func sendProgress(ch chan<- string, msg string) {
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func loadedToolsSkills(p PoolCaller) string {
	nTools, nSkills := 0, 0
	if reg := p.Tools(); reg != nil {
		nTools = len(reg.List())
	}
	if lib := p.Skills(); lib != nil {
		nSkills = len(lib.List())
	}
	return fmt.Sprintf(" · %d tools · %d skills", nTools, nSkills)
}

func mcpEnabled(p PoolCaller) bool {
	if mp, ok := p.(*pool.ModelPool); ok {
		return mp.MCPConfig != ""
	}
	return false
}

func mcpSuffix(on bool) string {
	if on {
		return " · Playwright MCP ON"
	}
	return ""
}

func poolModelLabels(p PoolCaller) string {
	if mp, ok := p.(*pool.ModelPool); ok {
		labels := make([]string, len(mp.Candidates))
		for i, m := range mp.Candidates {
			labels[i] = m.Label()
		}
		return strings.Join(labels, ", ")
	}
	return "stub"
}

func primaryModelLabel(p PoolCaller) string {
	if mp, ok := p.(*pool.ModelPool); ok && len(mp.Candidates) > 0 {
		return mp.Candidates[0].Label()
	}
	return ""
}

func validateConcurrency(p PoolCaller) int {
	if mp, ok := p.(*pool.ModelPool); ok {
		n := len(mp.Candidates)
		if n < 2 {
			return 2
		}
		return n
	}
	return 2
}
