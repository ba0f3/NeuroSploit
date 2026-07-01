package pipeline

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/toolloop"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

var targetLineRe = regexp.MustCompile(`(?m)^Target:\s*(\S+)\s*$`)

func targetFromPrompt(user string) string {
	if m := targetLineRe.FindStringSubmatch(user); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func hostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	}
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host
}

// defaultToolArgs builds minimal argv args for a registry tool from a target URL.
func defaultToolArgs(tool tools.Tool, target string) (map[string]any, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, false
	}
	host := hostFromTarget(target)
	args := map[string]any{}
	for _, p := range tool.Parameters {
		if !p.Required {
			continue
		}
		switch {
		case p.TargetFormat == "host" || p.TargetFormat == "host_or_ip" || p.TargetFormat == "domain" || p.TargetFormat == "ip":
			args[p.Name] = host
		case p.TargetFormat == "url":
			args[p.Name] = target
		case p.TargetFormat == "url_with_fuzz":
			return nil, false
		case p.Name == "target" || p.Name == "url":
			args[p.Name] = target
		case p.Name == "host" || p.Name == "domain":
			args[p.Name] = host
		default:
			return nil, false
		}
	}
	if len(args) == 0 {
		args["target"] = target
	}
	validation := tools.ValidateCall(tool, args, target)
	if !validation.Runnable {
		return nil, false
	}
	return validation.Args, true
}

func runBootstrapTools(ctx context.Context, executor tools.Executor, target string, toolList []tools.Tool, progress chan<- string) []toolloop.Observation {
	if executor == nil || target == "" || len(toolList) == 0 {
		return nil
	}
	var observations []toolloop.Observation
	for i, tool := range toolList {
		args, ok := defaultToolArgs(tool, target)
		if !ok {
			continue
		}
		call := tools.ToolCall{
			Name: tool.Name,
			ID:   fmt.Sprintf("bootstrap_%d", i+1),
			Args: args,
		}
		sendProgress(progress, fmt.Sprintf("tool run: %s", call.Name))
		callCtx := tools.ContextWithIteration(ctx, 1)
		result, err := executor.Execute(callCtx, call)
		if err != nil {
			result = tools.ToolResult{IsError: true, Error: err.Error()}
		}
		sendProgress(progress, toolloop.FormatToolProgress(call.Name, result))
		observations = append(observations, toolloop.Observation{Call: call, Result: result})
	}
	return observations
}

func bootstrapObservationsText(obs []toolloop.Observation) string {
	if len(obs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nREGISTRY TOOL OBSERVATIONS (already executed; synthesize recon JSON from these):\n")
	for i, o := range obs {
		fmt.Fprintf(&b, "\n### %d. %s\n", i+1, o.Call.Name)
		if o.Result.IsError {
			fmt.Fprintf(&b, "status: error — %s\n", o.Result.Error)
			continue
		}
		out := o.Result.Output
		if len(out) > 6000 {
			out = out[:6000] + "\n... [truncated]"
		}
		fmt.Fprintf(&b, "status: ok (exit %d)\n```\n%s\n```\n", o.Result.ExitCode, out)
	}
	return b.String()
}
