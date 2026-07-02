package reconcache

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func IsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func Resolve(cfg types.RunConfig, bundle *Bundle, tty bool) (types.ReconPolicy, error) {
	switch cfg.ReconPolicy {
	case types.ReconPolicyNew:
		return types.ReconPolicyNew, nil
	case types.ReconPolicyReuse:
		if bundle == nil {
			return "", fmt.Errorf("no recon cache for %s; run with --recon new", Slug(cfg.Target))
		}
		return types.ReconPolicyReuse, nil
	case types.ReconPolicyAsk:
		if bundle == nil {
			return types.ReconPolicyNew, nil
		}
		if tty {
			return types.ReconPolicyAsk, nil
		}
		return types.ReconPolicyReuse, nil
	default:
		if bundle == nil {
			return types.ReconPolicyNew, nil
		}
		if tty {
			return types.ReconPolicyAsk, nil
		}
		return types.ReconPolicyReuse, nil
	}
}

func PromptReuse(bundle *Bundle, listRuns func() []RunEntry) (types.ReconPolicy, error) {
	for {
		warn := ""
		if bundle.StaleWarning() {
			warn = " [stale: >7 days]"
		}
		tools := len(bundle.Manifest.Tools)
		fmt.Fprintf(os.Stderr,
			"Found recon for %s (%s, %d tools, from %s)%s\n[R] Reuse  [N] New scan  [L] List prior runs  [Q] Quit\n> ",
			bundle.Slug, FormatAge(bundle.Age()), tools, bundle.SourceRunBase(), warn)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "r", "reuse":
			return types.ReconPolicyReuse, nil
		case "n", "new":
			return types.ReconPolicyNew, nil
		case "l", "list":
			for i, e := range listRuns() {
				fmt.Fprintf(os.Stderr, "  %d. %s (%s)\n", i+1, filepath.Base(e.Dir), FormatAge(e.Age))
			}
		case "q", "quit":
			os.Exit(0)
		}
	}
}
