package engagement

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
)

var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

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
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return false
	}
	return validHostIdentifier(target)
}

// validHostIdentifier accepts IPs and simple hostnames (optional :port).
func validHostIdentifier(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if strings.ContainsAny(target, ";/$&|`()") {
		return false
	}
	host := target
	if h, port, err := net.SplitHostPort(target); err == nil && port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return false
		}
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 || strings.HasPrefix(host, "-") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || !hostnameLabelRe.MatchString(label) {
			return false
		}
	}
	return true
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
