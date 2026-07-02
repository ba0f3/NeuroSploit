package tools

import (
	"os"
	"os/exec"
	"strings"
	"sync"
)

type httpxFlavor string

const (
	httpxProjectDiscovery httpxFlavor = "projectdiscovery"
	httpxPython           httpxFlavor = "python"
)

var (
	httpxFlavorOnce sync.Once
	httpxFlavorVal  httpxFlavor
)

// HttpxFlavor reports which httpx CLI is first on PATH (cached).
func HttpxFlavor() httpxFlavor {
	httpxFlavorOnce.Do(func() {
		httpxFlavorVal = detectHttpxFlavor()
	})
	return httpxFlavorVal
}

// ResetHttpxFlavorCache clears cached flavor detection (tests only).
func ResetHttpxFlavorCache() {
	httpxFlavorOnce = sync.Once{}
	httpxFlavorVal = ""
}

func detectHttpxFlavor() httpxFlavor {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("NS_HTTPX_FLAVOR"))); v != "" {
		switch v {
		case "projectdiscovery", "pd":
			return httpxProjectDiscovery
		case "python", "kali":
			return httpxPython
		}
	}
	if _, err := exec.LookPath("httpx"); err != nil {
		return httpxPython
	}
	for _, args := range [][]string{{"-version"}, {"-h"}, {"--help"}} {
		out, err := exec.Command("httpx", args...).CombinedOutput()
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "projectdiscovery") {
			return httpxProjectDiscovery
		}
	}
	return httpxPython
}

func adaptToolArgv(tool Tool, argv []string) []string {
	if tool.Name != "httpx" {
		return argv
	}
	if HttpxFlavor() == httpxPython {
		return adaptHttpxPython(argv)
	}
	return argv
}

func adaptHttpxPython(argv []string) []string {
	if len(argv) == 0 || argv[0] != "httpx" {
		return argv
	}
	var url string
	var follow bool
	var extras []string
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-u" && i+1 < len(argv):
			url = argv[i+1]
			i++
		case strings.HasPrefix(arg, "-u") && len(arg) > 2:
			url = arg[2:]
		case arg == "-follow-redirects" || arg == "-fr":
			follow = true
		case arg == "-silent" || arg == "-status-code" || arg == "-title" || arg == "-tech-detect" ||
			arg == "-sc" || arg == "-td":
			continue
		default:
			extras = append(extras, arg)
		}
	}
	if url == "" {
		return argv
	}
	out := []string{"httpx", url}
	if follow {
		out = append(out, "--follow-redirects")
	}
	out = append(out, extras...)
	return out
}
