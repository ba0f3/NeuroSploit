package pipeline

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
)

func selectAgents(p PoolCaller, recon, focus string, catalog []agents.Agent, progress chan<- string) []string {
	var list strings.Builder
	for _, a := range catalog {
		fmt.Fprintf(&list, "%s — %s [%s]\n", a.Name, strings.ReplaceAll(a.Title, " Agent", ""), a.CWE)
	}
	reconTrim := recon
	if len([]rune(reconTrim)) > 3000 {
		reconTrim = string([]rune(reconTrim)[:3000])
	}
	focusLine := ""
	if strings.TrimSpace(focus) != "" {
		focusLine = fmt.Sprintf("OPERATOR FOCUS (strongly prioritise agents for this): %s\n\n", focus)
	}
	user := fmt.Sprintf("%sRECON:\n%s\n\nAGENT CATALOG (name — title [cwe]):\n%s\n\nReturn a JSON array of agent names to run.",
		focusLine, reconTrim, list.String())
	m, text, err := p.Complete("select", pool.TaskSelect, selectSys, user)
	if err != nil {
		sendProgress(progress, fmt.Sprintf("agent selection failed (%v) — falling back to RL ranking", err))
		return nil
	}
	names := parseStringArray(text)
	if len(names) == 0 {
		preview := text
		if len([]rune(preview)) > 120 {
			preview = string([]rune(preview)[:120])
		}
		preview = strings.ReplaceAll(preview, "\n", " ")
		sendProgress(progress, fmt.Sprintf("agent selection via %s returned no parseable list (%d chars): %s", m.Label(), utf8.RuneCountInString(text), preview))
	} else {
		sendProgress(progress, fmt.Sprintf("agent selection via %s → %d agent(s) chosen", m.Label(), len(names)))
	}
	return names
}

var baselineAgents = []string{
	"sqli_error", "sqli_blind", "sqli_union", "xss_reflected", "xss_stored", "xss_dom",
	"command_injection", "lfi", "path_traversal", "ssrf", "idor", "open_redirect",
	"auth_bypass", "csrf", "ssti", "file_upload", "xxe", "information_disclosure",
	"security_headers", "cors_misconfig",
}

var reconSignals = []struct {
	sig   string
	names []string
}{
	{"graphql", []string{"graphql"}},
	{"jwt", []string{"jwt"}},
	{"oauth", []string{"oauth", "oidc", "saml"}},
	{"\"jwt\"", []string{"jwt"}},
	{"api", []string{"api_", "bola", "bfla", "idor", "mass_assign", "rate_limit"}},
	{"upload", []string{"file_upload", "zip_slip"}},
	{"websocket", []string{"websocket"}},
	{"\"ws\"", []string{"websocket"}},
	{"graphql", []string{"graphql"}},
	{"aws", []string{"aws_", "s3_", "imds", "cloud_"}},
	{"gcp", []string{"gcp_", "gcs_", "metadata"}},
	{"azure", []string{"azure_"}},
	{"kubernetes", []string{"k8s_", "kubelet"}},
	{"docker", []string{"docker_", "container_"}},
	{"ai_features", []string{"llm_", "prompt_injection", "rag", "vector_db"}},
	{"chat", []string{"llm_", "prompt_injection"}},
	{"jinja", []string{"ssti"}},
	{"flask", []string{"ssti", "ssrf", "command_injection"}},
	{"php", []string{"lfi", "rfi", "sqli", "command_injection"}},
	{"template", []string{"ssti", "csti"}},
	{"redirect", []string{"open_redirect"}},
	{"login", []string{"auth_bypass", "brute_force", "sqli", "default_credentials", "cleartext"}},
	{"comments", []string{"xss_stored", "xss_reflected", "sqli"}},
	{"aspx", []string{"aspnet_", "sqli", "xss"}},
	{"asp.net", []string{"aspnet_", "viewstate", "sqli"}},
	{"search", []string{"xss", "sqli"}},
	{"cache", []string{"cache", "smuggl"}},
}

func heuristicSelect(ranked []agents.Agent, recon, focus string, cap int) []agents.Agent {
	r := strings.ToLower(recon)
	f := strings.ToLower(focus)
	type scored struct {
		score int
		agent agents.Agent
	}
	var scoredList []scored
	for _, a := range ranked {
		score := 0
		for _, b := range baselineAgents {
			if a.Name == b {
				score += 4
				break
			}
		}
		for _, sig := range reconSignals {
			if strings.Contains(r, sig.sig) {
				for _, n := range sig.names {
					if strings.Contains(a.Name, n) {
						score += 6
						break
					}
				}
			}
		}
		for _, tok := range strings.Split(a.Name, "_") {
			if len(tok) >= 4 && strings.Contains(r, tok) {
				score += 2
			}
		}
		if f != "" {
			blob := strings.ToLower(a.Name + " " + a.Title)
			keywords := []string{"inject", "sqli", "xss", "ssrf", "ssti", "rce", "command", "lfi", "rfi",
				"idor", "bola", "bfla", "access", "auth", "privilege", "csrf", "redirect",
				"deserial", "xxe", "traversal", "upload", "jwt", "secret", "crypto"}
			for _, kw := range keywords {
				if strings.Contains(f, kw) && strings.Contains(blob, kw) {
					score += 10
					break
				}
			}
		}
		scoredList = append(scoredList, scored{score: score, agent: a})
	}
	sort.Slice(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})
	var out []agents.Agent
	for _, s := range scoredList {
		if s.score > 0 {
			out = append(out, s.agent)
		}
	}
	if len(out) == 0 {
		out = append(out, ranked...)
	}
	if cap > 0 && len(out) > cap {
		out = out[:cap]
	}
	return out
}
