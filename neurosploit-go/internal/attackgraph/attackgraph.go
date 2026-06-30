package attackgraph

import (
	"strconv"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// STAGE_ORDER is the kill-chain ordering used for grouping and sorting.
var STAGE_ORDER = []string{
	"recon", "initial-access", "execution", "credential-access", "privesc", "lateral", "exfil", "impact",
}

// mapCwe maps a CWE identifier to (OWASP Top 10 2021, MITRE ATT&CK technique, kill-chain stage).
func mapCwe(cwe string) (owasp, mitre, stage string) {
	n := 0
	if s := strings.TrimPrefix(strings.ToLower(cwe), "cwe-"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			n = v
		}
	}
	switch n {
	case 89, 943:
		return "A03:2021-Injection", "T1190", "initial-access"
	case 77, 78, 94, 95, 917, 1336:
		return "A03:2021-Injection", "T1059", "execution"
	case 79, 80:
		return "A03:2021-Injection", "T1059.007", "execution"
	case 90:
		return "A03:2021-Injection", "T1190", "initial-access"
	case 611, 776:
		return "A05:2021-Security-Misconfiguration", "T1190", "initial-access"
	case 918:
		return "A10:2021-SSRF", "T1090", "lateral"
	case 22, 23, 98, 73:
		return "A01:2021-Broken-Access-Control", "T1083", "execution"
	case 639, 862, 863, 284, 285:
		return "A01:2021-Broken-Access-Control", "T1078", "privesc"
	case 287, 384, 613, 620:
		return "A07:2021-Auth-Failures", "T1078", "initial-access"
	case 798, 522, 321, 256, 257, 312, 319:
		return "A07:2021-Auth-Failures", "T1552", "credential-access"
	case 502:
		return "A08:2021-Software-Data-Integrity", "T1059", "execution"
	case 327, 328, 916, 326, 330:
		return "A02:2021-Cryptographic-Failures", "T1600", "credential-access"
	case 200, 209, 538, 540, 532:
		return "A05:2021-Security-Misconfiguration", "T1592", "recon"
	case 601:
		return "A01:2021-Broken-Access-Control", "T1566", "initial-access"
	case 352:
		return "A01:2021-Broken-Access-Control", "T1189", "execution"
	case 434:
		return "A04:2021-Insecure-Design", "T1505.003", "execution"
	case 1321, 915:
		return "A08:2021-Software-Data-Integrity", "T1059", "execution"
	case 400, 770, 1333, 799:
		return "A04:2021-Insecure-Design", "T1499", "impact"
	default:
		return "A04:2021-Insecure-Design", "T1190", "initial-access"
	}
}

func exploitability(severity string, confidence float64) string {
	if confidence >= 0.85 {
		return "trivial"
	}
	if strings.EqualFold(severity, "Critical") || strings.EqualFold(severity, "High") {
		return "moderate"
	}
	return "hard"
}

// Enrich fills in empty mapping fields on each finding without overwriting model-set values.
func Enrich(findings *[]types.Finding) {
	for i := range *findings {
		f := &(*findings)[i]
		owasp, mitre, stage := mapCwe(f.CWE)
		if f.OWASP == "" {
			f.OWASP = owasp
		}
		if f.MITRE == "" {
			f.MITRE = mitre
		}
		if f.Stage == "" {
			f.Stage = stage
		}
		if f.Exploitability == "" {
			f.Exploitability = exploitability(f.Severity, f.Confidence)
		}
		if f.BusinessImpact == "" {
			f.BusinessImpact = f.Impact
		}
	}
}

func stageRank(s string) int {
	for i, st := range STAGE_ORDER {
		if st == s {
			return i
		}
	}
	return len(STAGE_ORDER)
}

// Mermaid renders a Mermaid flowchart of the attack path.
func Mermaid(findings []types.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	out := "flowchart LR\n"
	byStage := make(map[int][]*types.Finding)
	for i := range findings {
		f := &findings[i]
		r := stageRank(f.Stage)
		byStage[r] = append(byStage[r], f)
	}
	for r := 0; r <= len(STAGE_ORDER); r++ {
		group, ok := byStage[r]
		if !ok {
			continue
		}
		stage := "other"
		if r < len(STAGE_ORDER) {
			stage = STAGE_ORDER[r]
		}
		out += "  subgraph S" + strconv.Itoa(r) + "[\"" + stage + "\"]\n"
		for _, f := range group {
			out += "    " + nodeID(f) + "[\"" + esc(f.Title) + "<br/>" + esc(f.Severity) + " · " + esc(f.OWASP) + "\"]\n"
		}
		out += "  end\n"
	}
	ids := make(map[string]*types.Finding)
	for i := range findings {
		f := &findings[i]
		ids[f.ID] = f
	}
	hadEdge := false
	for i := range findings {
		f := &findings[i]
		for _, src := range f.ChainsFrom {
			if sf, ok := ids[src]; ok {
				out += "  " + nodeID(sf) + " --> " + nodeID(f) + "\n"
				hadEdge = true
			}
		}
	}
	if !hadEdge && len(byStage) > 1 {
		ranks := make([]int, 0, len(byStage))
		for r := range byStage {
			ranks = append(ranks, r)
		}
		for i := 0; i < len(ranks); i++ {
			for j := i + 1; j < len(ranks); j++ {
				if ranks[j] < ranks[i] {
					ranks[i], ranks[j] = ranks[j], ranks[i]
				}
			}
		}
		for i := 0; i < len(ranks)-1; i++ {
			a := byStage[ranks[i]]
			b := byStage[ranks[i+1]]
			if len(a) > 0 && len(b) > 0 {
				out += "  " + nodeID(a[0]) + " -.-> " + nodeID(b[0]) + "\n"
			}
		}
	}
	return out
}

// ASCIIKillchain renders a compact ASCII kill-chain table for the REPL.
func ASCIIKillchain(findings []types.Finding) string {
	if len(findings) == 0 {
		return "  (no findings to map)"
	}
	byStage := make(map[int][]*types.Finding)
	for i := range findings {
		f := &findings[i]
		r := stageRank(f.Stage)
		byStage[r] = append(byStage[r], f)
	}
	for r := range byStage {
		group := byStage[r]
		for i := range group {
			for j := i + 1; j < len(group); j++ {
				if types.SeverityRank(group[i].Severity) < types.SeverityRank(group[j].Severity) {
					group[i], group[j] = group[j], group[i]
				}
			}
		}
	}
	out := ""
	for r := 0; r <= len(STAGE_ORDER); r++ {
		group, ok := byStage[r]
		if !ok {
			continue
		}
		stage := "other"
		if r < len(STAGE_ORDER) {
			stage = STAGE_ORDER[r]
		}
		for _, f := range group {
			out += "  ▸ " + pad(stage, 16) + " [" + f.Severity + "] " + f.Title + " (" + f.MITRE + ")\n"
		}
	}
	return out
}

func nodeID(f *types.Finding) string {
	return "n" + sanitizeID(f.ID)
}

func sanitizeID(s string) string {
	var out strings.Builder
	for i, r := range s {
		if i >= 24 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		} else {
			out.WriteRune('_')
		}
	}
	return out.String()
}

func esc(s string) string {
	repl := strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "\"", "'")
	repl = strings.ReplaceAll(repl, "\n", " ")
	runes := []rune(repl)
	if len(runes) > 60 {
		runes = runes[:60]
	}
	return string(runes)
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

