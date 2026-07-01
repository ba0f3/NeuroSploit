package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/toolloop"
)

// finalizeReconText turns a toolloop/API response into compact recon JSON when possible.
func finalizeReconText(raw string) string {
	content := models.ExtractChatContent(raw)
	content = stripCodeFences(content)
	if obj := extractJSONSlice(content); json.Valid([]byte(obj)) {
		return obj
	}
	if obj := extractJSONSlice(raw); json.Valid([]byte(obj)) {
		return obj
	}
	if content != "" {
		return content
	}
	return raw
}

func formatToolLog(obs []toolloop.Observation) string {
	if len(obs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, o := range obs {
		fmt.Fprintf(&b, "## %d. %s\n", i+1, o.Call.Name)
		if len(o.Call.Args) > 0 {
			args, _ := json.Marshal(o.Call.Args)
			fmt.Fprintf(&b, "args: `%s`\n", args)
		}
		if o.Result.IsError {
			fmt.Fprintf(&b, "status: **error** — %s\n\n", o.Result.Error)
			continue
		}
		out := o.Result.Output
		if len(out) > 4000 {
			out = out[:4000] + "\n... [truncated]"
		}
		fmt.Fprintf(&b, "status: ok (%.1fs, exit %d)\n\n```\n%s\n```\n\n",
			o.Result.Duration.Seconds(), o.Result.ExitCode, out)
	}
	return b.String()
}
