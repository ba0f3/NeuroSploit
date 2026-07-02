package reconcache

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

func PromptReuse(defaultBundle *Bundle, listRuns func() []RunEntry) (types.ReconPolicy, *Bundle, error) {
	var listed []RunEntry
	selected := defaultBundle
	for {
		warn := ""
		if selected != nil && selected.StaleWarning() {
			warn = " [stale: >7 days]"
		}
		tools := 0
		from := "unknown"
		slug := "target"
		age := "unknown"
		if selected != nil {
			tools = len(selected.Manifest.Tools)
			from = selected.SourceRunBase()
			slug = selected.Slug
			age = FormatAge(selected.Age())
		}
		fmt.Fprintf(os.Stderr,
			"Found recon for %s (%s, %d tools, from %s)%s\n[R] Reuse  [N] New scan  [L] List prior runs  [Q] Quit\n> ",
			slug, age, tools, from, warn)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		choice := strings.TrimSpace(line)
		switch strings.ToLower(choice) {
		case "", "r", "reuse":
			if selected == nil {
				return types.ReconPolicyNew, nil, nil
			}
			return types.ReconPolicyReuse, selected, nil
		case "n", "new":
			return types.ReconPolicyNew, nil, nil
		case "l", "list":
			listed = listRuns()
			printRunList(listed)
		case "q", "quit":
			os.Exit(0)
		default:
			if n, ok := ParseRunChoice(choice); ok {
				if len(listed) == 0 {
					listed = listRuns()
				}
				if n < 1 || n > len(listed) {
					fmt.Fprintf(os.Stderr, "invalid choice %d (pick 1-%d, or L to list)\n", n, len(listed))
					continue
				}
				b, err := BundleFromRun(listed[n-1].Dir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "cannot load run: %v\n", err)
					continue
				}
				selected = b
				return types.ReconPolicyReuse, selected, nil
			}
		}
	}
}

func printRunList(listed []RunEntry) {
	if len(listed) == 0 {
		fmt.Fprintln(os.Stderr, "  (no prior runs with recon.json)")
		return
	}
	for i, e := range listed {
		fmt.Fprintf(os.Stderr, "  %d. %s (%s)\n", i+1, filepath.Base(e.Dir), FormatAge(e.Age))
	}
	fmt.Fprintln(os.Stderr, "Enter 1-N to reuse that run, or R/N/Q")
}

func ParseRunChoice(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
