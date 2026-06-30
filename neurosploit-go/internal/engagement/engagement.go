package engagement

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeTarget makes a filesystem-safe slug from a URL or path.
func SanitizeTarget(target string) string {
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

// BuildPool constructs a model pool for a live engagement.
func BuildPool(cfg types.RunConfig, mcp bool, workdir, base string) *pool.ModelPool {
	var refs []models.ModelRef
	for _, s := range cfg.Models {
		refs = append(refs, models.ModelRefParse(s))
	}
	mcpConfig := ""
	if mcp && cfg.Subscription && len(refs) > 0 && models.MCPSupported(refs[0].Provider) {
		_ = models.EnsurePlaywrightMCP(cfg.Verbose)
		if models.UsesCursorCLI(refs) {
			mcpConfig, _ = models.WriteCursorMCPConfig(base, "")
		} else {
			mcpConfig, _ = models.WriteMCPConfig(workdir, "")
		}
	}
	concurrency := cfg.Concurrency
	if cfg.Subscription {
		concurrency = models.SubscriptionConcurrency(refs, concurrency)
	}
	p := pool.WithAuth(refs, concurrency, cfg.Subscription, mcpConfig)
	client := models.NewChatClient()
	client.Verbose = cfg.Verbose
	if models.UsesCursorCLI(refs) {
		client.CursorWorkspace = base
	}
	p.Client = client
	return p
}

// PrepareWorkdir sets cfg.Workdir and cfg.RLPath for a new run.
func PrepareWorkdir(base string, cfg *types.RunConfig) (string, error) {
	workdir := filepath.Join("runs", fmt.Sprintf("ns-%d-%s", time.Now().Unix(), SanitizeTarget(cfg.Target)))
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return "", err
	}
	cfg.Workdir = &workdir
	rlPath := filepath.Join(base, "data", "rl_state_go.json")
	cfg.RLPath = &rlPath
	_ = os.MkdirAll(filepath.Dir(rlPath), 0755)
	return workdir, nil
}

// Execute runs the pipeline for the given mode and returns output.
// progress receives live status lines; stub bypasses live model calls when non-nil.
func Execute(ctx context.Context, base string, cfg types.RunConfig, mode string, mcp bool, stub pipeline.PoolCaller, progress chan<- string) pipeline.RunOutput {
	lib := agents.Load(base)
	if _, err := PrepareWorkdir(base, &cfg); err != nil {
		if progress != nil {
			progress <- fmt.Sprintf("error: %v", err)
		}
		return pipeline.RunOutput{Target: cfg.Target}
	}
	workdir := *cfg.Workdir

	if cfg.Subscription {
		var refs []models.ModelRef
		for _, s := range cfg.Models {
			refs = append(refs, models.ModelRefParse(s))
		}
		cfg.Concurrency = models.SubscriptionConcurrency(refs, cfg.Concurrency)
	}

	var p pipeline.PoolCaller
	if stub != nil {
		p = stub
	} else {
		p = BuildPool(cfg, mcp, workdir, base)
	}

	switch mode {
	case "whitebox":
		return pipeline.RunWhitebox(ctx, cfg, lib, p, progress)
	case "greybox":
		return pipeline.RunGreybox(ctx, cfg, lib, p, progress)
	case "host":
		return pipeline.RunHost(ctx, cfg, lib, p, progress)
	default:
		return pipeline.Run(ctx, cfg, lib, p, progress)
	}
}
