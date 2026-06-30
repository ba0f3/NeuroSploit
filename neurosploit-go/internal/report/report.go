package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/attackgraph"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func sevRank(s string) int {
	switch s {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	default:
		return 4
	}
}

func sevColor(s string) string {
	switch s {
	case "Critical":
		return "#c0392b"
	case "High":
		return "#e67e22"
	case "Medium":
		return "#f1c40f"
	case "Low":
		return "#3498db"
	default:
		return "#7f8c8d"
	}
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// HTML renders a dark-themed HTML report for validated findings.
func HTML(target string, findings []types.Finding) string {
	sorted := append([]types.Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		return sevRank(sorted[i].Severity) < sevRank(sorted[j].Severity)
	})

	counts := map[string]int{}
	for _, f := range sorted {
		counts[f.Severity]++
	}
	var chips string
	if len(counts) == 0 {
		chips = `<span class=chip style=background:#27ae60>No validated findings</span>`
	} else {
		order := []string{"Critical", "High", "Medium", "Low", "Info"}
		for _, sev := range order {
			if n := counts[sev]; n > 0 {
				chips += fmt.Sprintf(`<span class=chip style=background:%s>%s: %d</span>`, sevColor(sev), esc(sev), n)
			}
		}
	}

	var rows strings.Builder
	for i, f := range sorted {
		fmt.Fprintf(&rows,
			`<section class=finding><h3><span class=sev style=background:%s>%s</span> %d. %s</h3>`+
				`<div class=m>%s · %s · CVSS %s · votes %s · conf %.2f</div>`+
				`<div class=m>Endpoint: %s</div>`+
				`<h4>Payload</h4><pre>%s</pre><h4>Evidence</h4><pre>%s</pre>`+
				`<h4>Impact</h4><p>%s</p><h4>Remediation</h4><p>%s</p></section>`,
			sevColor(f.Severity), esc(f.Severity), i+1, esc(f.Title),
			esc(f.Agent), esc(f.CWE), esc(f.CVSS), esc(f.Votes), f.Confidence,
			esc(f.Endpoint), esc(f.Payload), esc(f.Evidence), esc(f.Impact), esc(f.Remediation),
		)
	}
	body := rows.String()
	if body == "" {
		body = `<p><em>No validated findings were produced for this engagement.</em></p>`
	}

	graph := attackgraph.Mermaid(sorted)
	graphBlock := ""
	if graph != "" {
		var kc strings.Builder
		for _, f := range sorted {
			fmt.Fprintf(&kc, `<tr><td>%s</td><td><span class=sev style=background:%s>%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				esc(f.Stage), sevColor(f.Severity), esc(f.Severity), esc(f.Title),
				esc(f.OWASP), esc(f.MITRE), esc(f.Exploitability))
		}
		graphBlock = fmt.Sprintf(
			`<h2>Attack Path &amp; Kill Chain</h2><div class=mermaid>%s</div>`+
				`<table class=kc><tr><th>Stage</th><th>Sev</th><th>Finding</th><th>OWASP</th><th>MITRE</th><th>Exploitability</th></tr>%s</table>`+
				`<script type=module>import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';mermaid.initialize({startOnLoad:true,theme:'dark'});</script>`,
			graph, kc.String())
	}

	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset=utf-8><title>NeuroSploit Report — %s</title><style>`+
		`table.kc{border-collapse:collapse;width:100%%;margin:14px 0;font-size:13px}table.kc th,table.kc td{border:1px solid #e3e3e3;padding:6px 9px;text-align:left}`+
		`.mermaid{background:#0f1117;border-radius:10px;padding:16px;margin:14px 0;overflow:auto}`+
		`body{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:860px;margin:40px auto;padding:0 24px}`+
		`h1{margin:0}.meta{color:#666;margin:4px 0 18px}.chip{color:#fff;border-radius:999px;padding:4px 12px;margin-right:8px;font-size:13px;font-weight:600}`+
		`.finding{border:1px solid #e3e3e3;border-radius:12px;padding:16px 20px;margin:16px 0}.finding h3{margin:0 0 8px;font-size:16px}`+
		`.sev{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}.m{color:#666;font-size:12px}`+
		`pre{background:#0f1117;color:#dfe6f3;padding:11px;border-radius:8px;overflow:auto;font-size:12.5px}`+
		`h4{margin:12px 0 3px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#8b5cf6}`+
		`.b{color:#8b5cf6;font-weight:800}</style></head><body>`+
		`<h1><span class=b>NeuroSploit</span> Penetration Test Report</h1>`+
		`<div class=meta>Target: <b>%s</b> · Go harness · multi-model validated</div>`+
		`<div>%s</div>%s<h2>Findings (%d)</h2>%s`+
		`<p class=meta>Authorized testing only. Findings confirmed by multi-model adversarial voting.<br>NeuroSploit · by <b>Joas A Santos</b> &amp; <b>Red Team Leaders</b></p></body></html>`,
		esc(target), esc(target), chips, graphBlock, len(sorted), body)
}
