package pipeline

import "strings"

// expandSelectedAgents adds complementary specialists when recon/selection hints at
// injectable params or comment forms but the orchestrator picked only one variant.
func expandSelectedAgents(names []string, recon string) []string {
	if len(names) == 0 {
		return names
	}
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[n] = true
	}
	r := strings.ToLower(recon)
	var extra []string
	add := func(n string) {
		if !have[n] {
			have[n] = true
			extra = append(extra, n)
		}
	}

	sqliPicked := false
	for _, n := range names {
		if strings.HasPrefix(n, "sqli_") {
			sqliPicked = true
			break
		}
	}
	if sqliPicked || strings.Contains(r, "comments.aspx") || strings.Contains(r, "readnews.aspx") ||
		strings.Contains(r, `"params"`) {
		add("sqli_error")
		add("sqli_blind")
		add("sqli_union")
		add("sqli_time")
	}

	xssPicked := false
	for _, n := range names {
		if strings.HasPrefix(n, "xss_") {
			xssPicked = true
			break
		}
	}
	if xssPicked || strings.Contains(r, "comments.aspx") || strings.Contains(r, "tbcomment") ||
		strings.Contains(r, "signup.aspx") {
		add("xss_stored")
		add("xss_reflected")
	}

	if strings.Contains(r, "asp.net") || strings.Contains(r, "viewstate") || strings.Contains(r, "aspx") {
		add("aspnet_viewstate")
		add("aspnet_debug_trace")
	}

	return append(names, extra...)
}
