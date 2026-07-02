package chainengine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"golang.org/x/sync/errgroup"
)

const chainSeedsPerRound = 6

// SeedCaller runs one chain-from-seed LLM turn for a single foothold.
type SeedCaller interface {
	ChainFromSeed(ctx context.Context, seed types.Finding, loot []string, round, maxRounds int, recipeBlock string) ([]types.Finding, []string, error)
	StopExploiting() bool
}

// ValidateFunc validates candidate findings and returns only confirmed ones.
type ValidateFunc func(candidates []types.Finding) []types.Finding

// FindingKey returns a dedup key for a finding.
type FindingKeyFunc func(f types.Finding) string

// ExtractChain parses chain agent output into findings and loot.
type ExtractChainFunc func(text, agent string) ([]types.Finding, []string)

// Config drives a multi-round attack chain run.
type Config struct {
	Target       string
	Recon        string
	Directives   string
	ChainDepth   int
	Confirmed    []types.Finding
	Chains       []agents.Agent
	ChainSystem  string
	Doctrine     string
	Validate     ValidateFunc
	FindingKey   FindingKeyFunc
	ExtractChain ExtractChainFunc
	Dedup        func([]types.Finding) []types.Finding
}

// Engine runs v3.5.4 attack chaining: iterative, decision-driven post-exploitation pivots.
type Engine struct {
	Caller   SeedCaller
	Progress chan<- string
}

// Run executes attack-chain rounds; returns accumulated validated chain findings.
func (e *Engine) Run(ctx context.Context, cfg Config) []types.Finding {
	maxRounds := cfg.ChainDepth
	if maxRounds == 0 || len(cfg.Confirmed) == 0 || e.Caller == nil || e.Caller.StopExploiting() {
		return nil
	}
	if cfg.Validate == nil || cfg.FindingKey == nil || cfg.ExtractChain == nil {
		return nil
	}
	dedup := cfg.Dedup
	if dedup == nil {
		dedup = func(v []types.Finding) []types.Finding { return v }
	}

	recipes := recipeBlock(cfg.Chains)
	reconCtx := cfg.Recon
	if len([]rune(reconCtx)) > 2000 {
		reconCtx = string([]rune(reconCtx)[:2000])
	}
	_ = reconCtx

	var allNew []types.Finding
	var loot []string
	seen := make(map[string]bool)
	for _, f := range cfg.Confirmed {
		seen[cfg.FindingKey(f)] = true
	}

	frontier := append([]types.Finding(nil), cfg.Confirmed...)
	sort.Slice(frontier, func(i, j int) bool {
		return types.SeverityRank(frontier[i].Severity) > types.SeverityRank(frontier[j].Severity)
	})

	for round := 1; round <= maxRounds; round++ {
		if e.Caller.StopExploiting() || len(frontier) == 0 {
			break
		}
		seeds := frontier
		if len(seeds) > chainSeedsPerRound {
			seeds = seeds[:chainSeedsPerRound]
		}
		e.emit(fmt.Sprintf("⛓ attack-chain round %d/%d — expanding %d foothold(s), %d loot item(s)", round, maxRounds, len(seeds), len(loot)))

		lootSnapshot := append([]string(nil), loot...)
		type seedResult struct {
			findings []types.Finding
			loot     []string
		}
		results := make([]seedResult, len(seeds))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(4)
		for i, seed := range seeds {
			i, seed := i, seed
			g.Go(func() error {
				select {
				case <-gctx.Done():
					return gctx.Err()
				default:
				}
				fs, lt, err := e.Caller.ChainFromSeed(gctx, seed, lootSnapshot, round, maxRounds, recipes)
				if err != nil {
					return nil
				}
				results[i] = seedResult{findings: fs, loot: lt}
				return nil
			})
		}
		_ = g.Wait()

		var roundCands []types.Finding
		for _, r := range results {
			for _, l := range r.loot {
				dup := false
				for _, existing := range loot {
					if strings.EqualFold(existing, l) {
						dup = true
						break
					}
				}
				if !dup {
					loot = append(loot, l)
				}
			}
			roundCands = append(roundCands, r.findings...)
		}

		var fresh []types.Finding
		for _, f := range dedup(roundCands) {
			key := cfg.FindingKey(f)
			if seen[key] {
				continue
			}
			seen[key] = true
			fresh = append(fresh, f)
		}
		if len(fresh) == 0 {
			e.emit("⛓ no new paths this round — chain exhausted")
			break
		}

		validated := cfg.Validate(fresh)
		e.emit(fmt.Sprintf("⛓ round %d: +%d validated finding(s), %d loot item(s) total", round, len(validated), len(loot)))
		if len(validated) == 0 {
			break
		}
		allNew = append(allNew, validated...)
		frontier = validated
		sort.Slice(frontier, func(i, j int) bool {
			return types.SeverityRank(frontier[i].Severity) > types.SeverityRank(frontier[j].Severity)
		})
	}

	if len(allNew) > 0 {
		e.emit(fmt.Sprintf("⛓ attack-chaining added %d finding(s) across pivots", len(allNew)))
	}
	return allNew
}

func recipeBlock(chains []agents.Agent) string {
	if len(chains) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("KNOWN CHAIN RECIPES (apply any that fit):\n")
	for _, a := range chains {
		fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(a.Title, " Agent", ""))
	}
	b.WriteByte('\n')
	return b.String()
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
