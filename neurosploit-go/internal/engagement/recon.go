package engagement

import (
	"fmt"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/reconcache"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// PrepareRecon resolves reuse vs fresh recon and imports a cached bundle into workdir when reusing.
func PrepareRecon(cfg *types.RunConfig, progress chan<- string) error {
	if cfg.Workdir == nil {
		return nil
	}
	if cfg.ReconPolicy == types.ReconPolicyNew {
		return nil
	}
	slug := reconcache.Slug(cfg.Target)
	cacheRoot := cfg.ReconCachePath
	if cacheRoot == "" {
		cacheRoot = types.DefaultReconCachePath
	}
	var bundle *reconcache.Bundle
	var err error
	if cfg.ReconFromRun != "" {
		bundle, err = reconcache.BundleFromRun(cfg.ReconFromRun)
		if err != nil {
			return fmt.Errorf("--from-run: %w", err)
		}
	} else {
		bundle, _ = reconcache.Discover(cacheRoot, "runs", slug)
	}
	policy, err := reconcache.Resolve(*cfg, bundle, reconcache.IsTTY())
	if err != nil {
		return err
	}
	if policy == types.ReconPolicyAsk {
		policy, err = reconcache.PromptReuse(bundle, func() []reconcache.RunEntry {
			return reconcache.ListRuns("runs", slug, 10)
		})
		if err != nil {
			return err
		}
	}
	if policy != types.ReconPolicyReuse || bundle == nil {
		return nil
	}
	workdir := *cfg.Workdir
	if err := reconcache.Import(bundle, workdir); err != nil {
		if progress != nil {
			progress <- fmt.Sprintf("recon import failed (%v) — running fresh", err)
		}
		return nil
	}
	cfg.ResolvedReconDir = workdir
	if progress != nil {
		progress <- fmt.Sprintf("recon: reused from %s (%s)", bundle.Dir, reconcache.FormatAge(bundle.Age()))
	}
	return nil
}
