package engagement

import (
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
)

// DetectMode infers pipeline mode from REPL/CLI session state.
func DetectMode(repo, target string, cr *creds.Creds) (string, error) {
	switch {
	case repo != "" && target != "":
		return "greybox", nil
	case repo != "":
		return "whitebox", nil
	case target != "":
		if isHostTarget(target, cr) {
			return "host", nil
		}
		return "run", nil
	default:
		return "", fmt.Errorf("set /target and/or /repo first")
	}
}

func isHostTarget(target string, cr *creds.Creds) bool {
	if cr == nil || cr.HostInstruction() == nil {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(target))
	return !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://")
}

// NormalizeURL prepends https:// when the target lacks a scheme.
func NormalizeURL(url string) string {
	u := strings.TrimSpace(url)
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://" + u
}

// ModeLabel returns a human-readable mode name for REPL /show output.
func ModeLabel(mode string) string {
	switch mode {
	case "greybox":
		return "greybox (code + live)"
	case "whitebox":
		return "white-box (code)"
	case "host":
		return "host/infra"
	case "run":
		return "black-box (live)"
	default:
		return mode
	}
}
