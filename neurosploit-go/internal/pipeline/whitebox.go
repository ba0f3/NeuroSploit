package pipeline

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/rl"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/toolloop"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"golang.org/x/sync/errgroup"
)

var sourceExts = map[string]bool{
	"rs": true, "py": true, "js": true, "ts": true, "tsx": true, "jsx": true,
	"go": true, "java": true, "php": true, "rb": true, "c": true, "cc": true,
	"cpp": true, "h": true, "hpp": true, "cs": true, "kt": true, "swift": true,
	"scala": true, "sh": true, "sql": true, "html": true, "vue": true,
	"yml": true, "yaml": true, "tf": true,
}

var skipPathMarkers = []string{"/.git/", "/node_modules/", "/target/", "/vendor/"}

// RunWhitebox analyses a repository's source for vulnerabilities.
func RunWhitebox(ctx context.Context, cfg types.RunConfig, lib agents.Library, p PoolCaller, progress chan<- string) RunOutput {
	p.SetProgress(progress)
	sendProgress(progress, fmt.Sprintf("WHITEBOX · repo: %s · %d code agents%s · models: %s",
		cfg.Target, len(lib.Code), loadedToolsSkills(p), poolModelLabels(p)))

	context := collectRepoContext(cfg.Target, 200, 120_000)
	bytes := len(context)
	sendProgress(progress, fmt.Sprintf("collected %d bytes of source context", bytes))
	if bytes == 0 {
		sendProgress(progress, "no readable source found at the given path")
	}

	var rlState rl.State
	if cfg.RLPath != nil {
		rlState = rl.Load(*cfg.RLPath)
	}
	ranked := lib.Code
	if len(ranked) == 0 {
		ranked = lib.Vulns
	}
	ranked = rankAgents(ranked, rlState)
	cap := agentCap(len(ranked), cfg.MaxAgents)
	selected := takeAgents(ranked, cap)
	sendProgress(progress, fmt.Sprintf("selected %d code-analysis agents", len(selected)))

	if cfg.Offline || bytes == 0 {
		artifacts := persist(cfg, "{}", context, "", nil)
		return buildOutput(cfg, "", nil, selected, 0, artifacts)
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
			body := agents.RenderPrompt(ag.User, map[string]string{
				"target":     "the provided repository",
				"recon_json": "{}",
			})
			user := fmt.Sprintf(
				"%s\n\nSOURCE CODE TO REVIEW:\n```\n%s\n```\n\nReply ONLY with a JSON array of findings (may be empty []). "+
					"Each item: {id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence} "+
					"where `endpoint` is the file:line and `evidence` quotes the vulnerable code.",
				body, context,
			)
			m, text, err := p.Complete(ag.Name, pool.TaskExploit, ag.System, user)
			if err != nil {
				sendProgress(progress, fmt.Sprintf("analyze %s failed: %v", ag.Name, err))
				results[i] = exploitResult{name: ag.Name, text: fmt.Sprintf("ERROR: %v", err)}
				return nil
			}
			f := extractFindings(text, ag.Name)
			sendProgress(progress, fmt.Sprintf("analyze %s via %s → %d candidate(s)", ag.Name, m.Label(), len(f)))
			results[i] = exploitResult{name: ag.Name, text: text, findings: f}
			return nil
		})
	}
	_ = g.Wait()

	transcript := transcriptOf(results)
	candidates := dedupFindings(flattenFindings(results))
	sendProgress(progress, fmt.Sprintf("%d candidate finding(s) (deduped) — validating", len(candidates)))
	findings := validate(candidates, p, codeVoteSys, cfg.VoteN, progress)
	findings = refutePass(findings, p, cfg.VoteN, progress)
	return finish(cfg, "{}", transcript, "", findings, selected, &rlState, progress)
}

// RunGreybox reviews source code and exploits the running app in one pipeline.
func RunGreybox(ctx context.Context, cfg types.RunConfig, lib agents.Library, p PoolCaller, progress chan<- string) RunOutput {
	p.SetProgress(progress)
	repo := ""
	if cfg.Repo != nil {
		repo = *cfg.Repo
	}
	sendProgress(progress, fmt.Sprintf("GREYBOX · live: %s · repo: %s · %d code agents%s",
		cfg.Target, repo, len(lib.Code), loadedToolsSkills(p)))

	mcpOn := mcpEnabled(p)
	recon, toolLog := runRecon(ctx, cfg, p, progress, mcpOn)

	context := collectRepoContext(repo, 200, 90_000)
	sendProgress(progress, fmt.Sprintf("collected %d bytes of source for code review", len(context)))

	var rlState rl.State
	if cfg.RLPath != nil {
		rlState = rl.Load(*cfg.RLPath)
	}

	codeLeads := ""
	if !cfg.Offline && context != "" {
		codeCap := len(lib.Code)
		if cfg.MaxAgents > 0 && cfg.MaxAgents < codeCap {
			codeCap = cfg.MaxAgents
		}
		if codeCap > 12 {
			codeCap = 12
		}
		codeAgents := takeAgents(lib.Code, codeCap)
		leads := parallelCodeReview(ctx, cfg, codeAgents, p, progress, context)
		leads = dedupFindings(leads)
		if len(leads) > 0 {
			var b strings.Builder
			b.WriteString("CODE-REVIEW LEADS (confirm these against the LIVE app):\n")
			for i, l := range leads {
				if i >= 25 {
					break
				}
				fmt.Fprintf(&b, "- [%s] %s @ %s (%s)\n", l.Severity, l.Title, l.Endpoint, l.CWE)
			}
			b.WriteByte('\n')
			codeLeads = b.String()
		}
		sendProgress(progress, fmt.Sprintf("%d code lead(s) → guiding live exploitation", len(leads)))
	}

	ranked := rankAgents(lib.Vulns, rlState)
	cap := agentCap(len(ranked), cfg.MaxAgents)
	focus := ""
	if cfg.Instructions != nil {
		focus = *cfg.Instructions
	}
	focus = strings.TrimSpace(focus + " " + codeLeads)

	if cfg.Offline {
		selected := takeAgents(ranked, cap)
		sendProgress(progress, fmt.Sprintf("offline: selected %d agent(s); no live exploitation", len(selected)))
		artifacts := persist(cfg, recon, codeLeads, toolLog, nil)
		return buildOutput(cfg, recon, nil, selected, 0, artifacts)
	}

	chosen := selectAgents(p, recon, focus, ranked, progress)
	selected := pickSelectedByName(ranked, chosen, recon, focus, cap, progress)
	selected = dedupAgentList(selected)
	sendProgress(progress, fmt.Sprintf("selected %d live agent(s): %s", len(selected), strings.Join(agentNames(selected), ", ")))

	builder := exploitUserBuilder{
		target:     cfg.Target,
		directives: operatorDirectives(cfg),
		mcpOn:      mcpOn,
		leads:      codeLeads,
		greybox:    true,
	}
	raw := parallelExploit(ctx, cfg, selected, p, progress, recon, mcpOn, builder)
	reconCtx := recon
	if len([]rune(reconCtx)) > 3000 {
		reconCtx = string([]rune(reconCtx)[:3000])
	}
	_ = reconCtx

	transcript := codeLeads + "\n" + transcriptOf(raw)
	candidates := dedupFindings(flattenFindings(raw))
	sendProgress(progress, fmt.Sprintf("%d candidate finding(s) (deduped) — validating", len(candidates)))
	findings := validate(candidates, p, voteSys, cfg.VoteN, progress)
	chained := runChainEngine(ctx, cfg, p, recon, findings, lib.Chains, progress, mcpOn)
	findings = append(findings, chained...)
	findings = dedupFindings(findings)
	findings = refutePass(findings, p, cfg.VoteN, progress)
	return finish(cfg, recon, transcript, toolLog, findings, selected, &rlState, progress)
}

// RunHost scans and tests an infrastructure target.
func RunHost(ctx context.Context, cfg types.RunConfig, lib agents.Library, p PoolCaller, progress chan<- string) RunOutput {
	p.SetProgress(progress)
	sendProgress(progress, fmt.Sprintf("HOST · target: %s · %d infra agents%s · models: %s",
		cfg.Target, len(lib.Infra), loadedToolsSkills(p), poolModelLabels(p)))

	recon, toolLog := runHostRecon(ctx, cfg, p, progress)

	var rlState rl.State
	if cfg.RLPath != nil {
		rlState = rl.Load(*cfg.RLPath)
	}
	ranked := rankAgents(lib.Infra, rlState)
	cap := agentCap(len(ranked), cfg.MaxAgents)
	focus := ""
	if cfg.Instructions != nil {
		focus = *cfg.Instructions
	}

	if cfg.Offline {
		selected := takeAgents(ranked, cap)
		sendProgress(progress, fmt.Sprintf("offline: selected %d infra agent(s); no live testing", len(selected)))
		artifacts := persist(cfg, recon, "", toolLog, nil)
		return buildOutput(cfg, recon, nil, selected, 0, artifacts)
	}

	chosen := selectAgents(p, recon, focus, ranked, progress)
	var selected []agents.Agent
	if len(chosen) > 0 {
		selected = pickSelectedByName(ranked, chosen, recon, focus, cap, progress)
		if len(selected) == 0 {
			selected = takeAgents(ranked, cap)
		}
	} else {
		selected = takeAgents(ranked, cap)
	}
	selected = dedupAgentList(selected)
	sendProgress(progress, fmt.Sprintf("selected %d infra agent(s): %s", len(selected), strings.Join(agentNames(selected), ", ")))

	builder := exploitUserBuilder{
		target:     cfg.Target,
		directives: operatorDirectives(cfg),
		host:       true,
	}
	raw := parallelExploit(ctx, cfg, selected, p, progress, recon, false, builder)
	transcript := transcriptOf(raw)
	candidates := dedupFindings(flattenFindings(raw))
	sendProgress(progress, fmt.Sprintf("%d candidate finding(s) (deduped) — validating", len(candidates)))
	findings := validate(candidates, p, voteSys, cfg.VoteN, progress)
	chained := runChainEngine(ctx, cfg, p, recon, findings, lib.Chains, progress, false)
	findings = append(findings, chained...)
	findings = dedupFindings(findings)
	findings = refutePass(findings, p, cfg.VoteN, progress)
	return finish(cfg, recon, transcript, toolLog, findings, selected, &rlState, progress)
}

func runHostRecon(ctx context.Context, cfg types.RunConfig, p PoolCaller, progress chan<- string) (string, string) {
	if cfg.Offline {
		return "{}", ""
	}
	select {
	case <-ctx.Done():
		return "{}", ""
	default:
	}
	user := fmt.Sprintf("%s%sTarget host: %s", operatorDirectives(cfg), hostTooling, cfg.Target)
	var m models.ModelRef
	var text string
	var toolLog string
	var err error
	if p.Tools() != nil && p.Executor() != nil {
		var obs []toolloop.Observation
		toolList := selectTools(p.Tools(), "host", nil)
		text, obs, err = runWithToolLoop(ctx, p, "recon", pool.TaskRecon, hostReconSys, user, toolList, progress)
		toolLog = formatToolLog(obs)
		text = finalizeReconText(text)
	} else {
		m, text, err = p.Complete("recon", pool.TaskRecon, hostReconSys, user)
		text = finalizeReconText(text)
	}
	if err != nil {
		sendProgress(progress, fmt.Sprintf("recon failed (%v)", err))
		return "{}", toolLog
	}
	if m.Label() != "" {
		sendProgress(progress, fmt.Sprintf("recon complete via %s", m.Label()))
	} else {
		sendProgress(progress, "recon complete")
	}
	return text, toolLog
}

func parallelCodeReview(ctx context.Context, cfg types.RunConfig, codeAgents []agents.Agent, p PoolCaller, progress chan<- string, context string) []types.Finding {
	var all []types.Finding
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	g.SetLimit(limit)
	for _, ag := range codeAgents {
		ag := ag
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}
			body := agents.RenderPrompt(ag.User, map[string]string{
				"target":     "the repository",
				"recon_json": "{}",
			})
			user := fmt.Sprintf(
				"%s\n\nSOURCE:\n```\n%s\n```\nReply ONLY a JSON array of issues (may be []): "+
					"{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence} where endpoint is file:line.",
				body, context,
			)
			_, text, err := p.Complete(ag.Name, pool.TaskSelect, ag.System, user)
			if err != nil {
				return nil
			}
			f := extractFindings(text, ag.Name)
			sendProgress(progress, fmt.Sprintf("review %s → %d lead(s)", ag.Name, len(f)))
			mu.Lock()
			all = append(all, f...)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return all
}

func collectRepoContext(root string, maxFiles, maxBytes int) string {
	root = filepath.Clean(root)
	if _, err := os.Stat(root); err != nil {
		return ""
	}
	var out strings.Builder
	files := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if files >= maxFiles || out.Len() >= maxBytes {
			return fs.SkipAll
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil && rel != "." && strings.Count(rel, string(os.PathSeparator)) >= 8 {
				return filepath.SkipDir
			}
			return nil
		}
		s := filepath.ToSlash(path)
		for _, marker := range skipPathMarkers {
			if strings.Contains(s, marker) {
				return nil
			}
		}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
		if !sourceExts[ext] {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		budget := maxBytes - out.Len()
		if budget <= 0 {
			return fs.SkipAll
		}
		take := len(content)
		if take > 8000 {
			take = 8000
		}
		if take > budget {
			take = budget
		}
		for take > 0 && !utf8.Valid(content[:take]) {
			take--
		}
		fmt.Fprintf(&out, "\n// ===== file: %s =====\n%s\n", rel, content[:take])
		files++
		return nil
	})
	return out.String()
}
