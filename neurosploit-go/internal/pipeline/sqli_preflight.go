package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// sqliPreflight runs deterministic sqlmap on injectable URLs before the LLM tool loop.
// skipLoop is true when at least one URL produced a confirmed finding (per_agent scope).
func sqliPreflight(ctx context.Context, p PoolCaller, ag agents.Agent, recon, target string, progress chan<- string) (findings []types.Finding, transcript string, skipLoop bool) {
	if p.Executor() == nil || p.Tools() == nil {
		return nil, "", false
	}
	if _, ok := p.Tools().Get("sqlmap"); !ok {
		return nil, "", false
	}
	urls := injectableURLs(recon, target)
	if len(urls) == 0 {
		return nil, "", false
	}
	var blocks []string
	for _, u := range urls {
		sendProgress(progress, fmt.Sprintf("preflight %s: sqlmap on %s", ag.Name, u))
		out, logPath, err := runSQLMapProbe(ctx, p.Executor(), u)
		if err != nil {
			blocks = append(blocks, fmt.Sprintf("SQLMAP %s:\nerror: %v", u, err))
			continue
		}
		blocks = append(blocks, fmt.Sprintf("SQLMAP %s:\n%s", u, truncateOut(out, 4000)))
		if f := parseSQLMapFinding(out, u, ag.Name, logPath); f != nil {
			findings = append(findings, *f)
		}
	}
	if len(blocks) == 0 {
		return findings, "", false
	}
	transcript = "--- PREFLIGHT SQLMAP ---\n" + strings.Join(blocks, "\n\n")
	skipLoop = len(findings) > 0
	return findings, transcript, skipLoop
}

func runSQLMapProbe(ctx context.Context, executor tools.Executor, targetURL string) (out, logPath string, err error) {
	call := tools.ToolCall{
		Name: "sqlmap",
		ID:   "sqlmap_probe",
		Args: sqlmapHarnessArgs(targetURL),
	}
	result, err := executor.Execute(ctx, call)
	if err != nil {
		return "", "", err
	}
	if result.IsError {
		return result.Error, result.LogPath, fmt.Errorf("%s", result.Error)
	}
	return result.Output, result.LogPath, nil
}
