package toolloop

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

// Caller invokes a language model with an optional list of tool definitions.
type Caller interface {
	// Call sends the current prompt to the model. toolsJSON is an OpenAI-compatible
	// function schema list. The returned string may be either a raw API response
	// (containing tool_calls) or a plain text answer (possibly with <tool_call> tags).
	Call(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error)
}

// CallerFunc adapts a function to the Caller interface.
type CallerFunc func(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error)

// Call implements the Caller interface.
func (f CallerFunc) Call(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error) {
	return f(ctx, system, user, toolsJSON)
}

// Loop runs a ReAct-style tool loop.
type Loop struct {
	Caller            Caller
	Executor          tools.Executor
	MaxIter           int
	MaxRepairAttempts int
	Progress          chan<- string
}

// Observation records one tool call and its result.
type Observation struct {
	Call   tools.ToolCall
	Result tools.ToolResult
}

// Run executes the tool loop until the model returns a final answer or MaxIter is reached.
func (l *Loop) Run(ctx context.Context, system, user string, toolList []tools.Tool) (string, []Observation, error) {
	if l.MaxIter == 0 {
		l.MaxIter = 10
	}
	if l.MaxRepairAttempts == 0 {
		l.MaxRepairAttempts = 2
	}
	invalidCounts := map[string]int{}
	toolsByName := map[string]tools.Tool{}
	for _, t := range toolList {
		toolsByName[t.Name] = t
	}
	toolDesc := renderToolPrompt(toolList)
	fullSystem := system + "\n\n" + toolDesc
	history := user
	var observations []Observation

	for i := 0; i < l.MaxIter; i++ {
		l.emit(fmt.Sprintf("toolloop iteration %d", i+1))
		response, err := l.Caller.Call(ctx, fullSystem, history, functionDefinitions(toolList))
		if err != nil {
			return "", observations, err
		}
		calls := parseToolCalls(response)
		if len(calls) == 0 {
			l.emit(fmt.Sprintf("toolloop final answer (%d tool(s) executed)", len(observations)))
			return response, observations, nil
		}
		for _, call := range calls {
			tool, ok := toolsByName[call.Name]
			if !ok {
				result := tools.ToolResult{Name: call.Name, ID: call.ID, IsError: true, Error: "VALIDATION_ERROR: unknown tool"}
				observations = append(observations, Observation{Call: call, Result: result})
				history += "\n\n" + formatObservation(call, result)
				continue
			}
			validation := tools.ValidateCall(tool, call.Args, "")
			if !validation.Runnable {
				key := invalidFingerprint(call, validation.Issues)
				invalidCounts[key]++
				result := tools.ToolResult{
					Name:    call.Name,
					ID:      call.ID,
					IsError: true,
					Error:   formatValidationObservation(call, validation),
				}
				l.emit(formatToolProgress(call.Name, result))
				observations = append(observations, Observation{Call: call, Result: result})
				history += "\n\n" + formatObservation(call, result)
				if invalidCounts[key] > l.MaxRepairAttempts {
					return "", observations, fmt.Errorf("repeated invalid tool call: %s", call.Name)
				}
				continue
			}
			if len(validation.Warnings) > 0 {
				history += "\n\n" + formatNormalizationObservation(call, validation)
			}
			call.Args = validation.Args
			l.emit(fmt.Sprintf("tool run: %s", call.Name))
			callCtx := tools.ContextWithIteration(ctx, i+1)
			result, err := l.Executor.Execute(callCtx, call)
			if err != nil {
				result = tools.ToolResult{IsError: true, Error: err.Error()}
			}
			l.emit(formatToolProgress(call.Name, result))
			observations = append(observations, Observation{Call: call, Result: result})
			history += "\n\n" + formatObservation(call, result)
		}
	}
	l.emit(fmt.Sprintf("toolloop done: %d tool(s) executed", len(observations)))
	return history, observations, fmt.Errorf("toolloop reached max iterations (%d)", l.MaxIter)
}

// FormatToolProgress renders a single progress line for a tool result (includes log path when set).
func FormatToolProgress(name string, result tools.ToolResult) string {
	return formatToolProgress(name, result)
}

func formatToolProgress(name string, result tools.ToolResult) string {
	var line string
	if result.IsError {
		msg := result.Error
		if len(msg) > 120 {
			msg = msg[:120] + "..."
		}
		line = fmt.Sprintf("tool err: %s (%s)", name, msg)
	} else {
		d := result.Duration
		if d <= 0 {
			d = time.Millisecond
		}
		line = fmt.Sprintf("tool ok: %s (%.1fs, exit %d, %d bytes)", name, d.Seconds(), result.ExitCode, len(result.Output))
	}
	if result.LogPath != "" {
		line += fmt.Sprintf(" → %s", result.LogPath)
	}
	return line
}

func (l *Loop) emit(msg string) {
	if l.Progress == nil {
		return
	}
	select {
	case l.Progress <- msg:
	default:
	}
}

func renderToolPrompt(toolList []tools.Tool) string {
	var b strings.Builder
	b.WriteString("AVAILABLE TOOLS\n")
	b.WriteString("You may call any of the following tools to gather evidence. " +
		"For each step, reason briefly, then either call a tool or give your final answer.\n\n")
	for _, t := range toolList {
		b.WriteString(fmt.Sprintf("- %s: %s\n", t.Name, t.ShortDescription))
		if len(t.Parameters) > 0 {
			b.WriteString("  Parameters:\n")
			for _, p := range t.Parameters {
				req := ""
				if p.Required {
					req = " (required)"
				}
				b.WriteString(fmt.Sprintf("    * %s (%s)%s - %s\n", p.Name, p.Type, req, p.Description))
			}
		}
	}
	b.WriteString("\nTOOL CALL FORMAT (use EXACTLY this format, one JSON object per block):\n")
	b.WriteString("<tool_call>\n")
	b.WriteString("{\"name\": \"TOOL_NAME\", \"arguments\": {\"param1\": \"value1\"}}\n")
	b.WriteString("</tool_call>\n\n")
	b.WriteString("RULES:\n")
	b.WriteString("1. Only use tools you have been given.\n")
	b.WriteString("2. Use the parameter names and formats exactly as documented; host-only tools do not accept full URLs.\n")
	b.WriteString("3. Wait for the observation after each tool call before deciding the next step.\n")
	b.WriteString("4. If you receive VALIDATION_ERROR, repair the exact parameter named in the observation and retry once with corrected arguments.\n")
	b.WriteString("5. When you have enough evidence, reply with your final answer only.\n")
	return b.String()
}

func functionDefinitions(toolList []tools.Tool) []map[string]any {
	var out []map[string]any
	for _, t := range toolList {
		out = append(out, t.FunctionDefinition())
	}
	return out
}

func formatObservation(call tools.ToolCall, result tools.ToolResult) string {
	status := "SUCCESS"
	if result.IsError {
		status = "ERROR"
	}
	out := result.Output
	if result.IsError {
		out = result.Error
	}
	// Truncate very long outputs to keep prompt size reasonable.
	if len(out) > 8000 {
		out = out[:8000] + "\n... [truncated]"
	}
	return fmt.Sprintf("OBSERVATION [tool=%s status=%s id=%s]:\n%s", call.Name, status, call.ID, out)
}

func formatValidationObservation(call tools.ToolCall, validation tools.ValidationResult) string {
	var b strings.Builder
	b.WriteString("VALIDATION_ERROR\n")
	for _, issue := range validation.Issues {
		fmt.Fprintf(&b, "parameter: %s\n", issue.Parameter)
		fmt.Fprintf(&b, "code: %s\n", issue.Code)
		fmt.Fprintf(&b, "expected: %s\n", issue.Expected)
		fmt.Fprintf(&b, "received: %s\n", issue.Received)
		if len(issue.Examples) > 0 {
			b.WriteString("examples:\n")
			for _, ex := range issue.Examples {
				fmt.Fprintf(&b, "- %s\n", ex)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func formatNormalizationObservation(call tools.ToolCall, validation tools.ValidationResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OBSERVATION [tool=%s status=NORMALIZED id=%s]:\n", call.Name, call.ID)
	for _, warning := range validation.Warnings {
		fmt.Fprintf(&b, "parameter: %s\nmessage: %s\noriginal: %v\nnormalized: %v\n", warning.Parameter, warning.Message, warning.Original, warning.Normalized)
	}
	return strings.TrimSpace(b.String())
}

func invalidFingerprint(call tools.ToolCall, issues []tools.ValidationIssue) string {
	var b strings.Builder
	b.WriteString(call.Name)
	for _, issue := range issues {
		fmt.Fprintf(&b, "|%s=%s:%s", issue.Parameter, issue.Code, issue.Received)
	}
	return b.String()
}

var toolCallTagRe = regexp.MustCompile(`<tool_call>\s*(\{.*?\})\s*</tool_call>`)

func parseToolCalls(response string) []tools.ToolCall {
	// 1. Try native OpenAI tool_calls format.
	if calls := parseNativeToolCalls(response); len(calls) > 0 {
		return calls
	}
	// 2. Fallback: <tool_call> JSON tags.
	return parseTagToolCalls(response)
}

func parseNativeToolCalls(response string) []tools.ToolCall {
	var raw map[string]any
	if err := json.Unmarshal([]byte(response), &raw); err != nil {
		return nil
	}
	choices, ok := raw["choices"].([]any)
	if !ok || len(choices) == 0 {
		return nil
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return nil
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return nil
	}
	callsAny, ok := message["tool_calls"].([]any)
	if !ok {
		return nil
	}
	var out []tools.ToolCall
	for _, c := range callsAny {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		fn, ok := m["function"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := fn["name"].(string)
		argsStr, _ := fn["arguments"].(string)
		var args map[string]any
		_ = json.Unmarshal([]byte(argsStr), &args)
		out = append(out, tools.ToolCall{Name: name, ID: id, Args: args})
	}
	return out
}

func parseTagToolCalls(response string) []tools.ToolCall {
	var out []tools.ToolCall
	matches := toolCallTagRe.FindAllStringSubmatch(response, -1)
	for i, m := range matches {
		var payload struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(m[1]), &payload); err != nil {
			continue
		}
		if payload.Name == "" {
			continue
		}
		id := fmt.Sprintf("tag_%d", i+1)
		out = append(out, tools.ToolCall{Name: payload.Name, ID: id, Args: payload.Arguments})
	}
	return out
}
