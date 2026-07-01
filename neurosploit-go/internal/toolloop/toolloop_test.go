package toolloop

import (
	"context"
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
)

type mockCaller struct {
	responses []string
	idx       int
}

func (m *mockCaller) Call(ctx context.Context, system, user string, toolsJSON []map[string]any) (string, error) {
	if m.idx >= len(m.responses) {
		return "", nil
	}
	resp := m.responses[m.idx]
	m.idx++
	return resp, nil
}

type mockExecutor struct {
	results map[string]tools.ToolResult
}

func (m *mockExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	if r, ok := m.results[call.Name]; ok {
		r.Name = call.Name
		r.ID = call.ID
		return r, nil
	}
	return tools.ToolResult{IsError: true, Error: "unknown tool: " + call.Name}, nil
}

func TestLoopTagToolCalls(t *testing.T) {
	caller := &mockCaller{
		responses: []string{
			"<tool_call>\n{\"name\": \"nmap\", \"arguments\": {\"target\": \"example.com\", \"ports\": \"80,443\"}}\n</tool_call>",
			"Open ports: 80, 443. No other findings.",
		},
	}
	exec := &mockExecutor{
		results: map[string]tools.ToolResult{
			"nmap": {Output: "PORT    STATE SERVICE\n80/tcp  open  http\n443/tcp open  https\n"},
		},
	}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 3}
	final, obs, err := loop.Run(context.Background(), "You are a tester.", "Scan example.com", []tools.Tool{
		{
			Name:             "nmap",
			Command:          "nmap",
			ShortDescription: "Port scanner",
			Parameters: []tools.Parameter{
				{Name: "target", Type: "string", Required: true, Format: "positional", Position: 0},
				{Name: "ports", Type: "string", Required: false, Flag: "-p", Format: "combined"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Call.Name != "nmap" {
		t.Fatalf("expected nmap call, got %s", obs[0].Call.Name)
	}
	if !strings.Contains(final, "Open ports") {
		t.Fatalf("unexpected final: %s", final)
	}
}

func TestLoopNativeToolCalls(t *testing.T) {
	caller := &mockCaller{
		responses: []string{
			`{"choices":[{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"curl","arguments":"{\"url\":\"http://example.com\"}"}}]}}]}`,
			"HTTP 200 OK",
		},
	}
	exec := &mockExecutor{
		results: map[string]tools.ToolResult{
			"curl": {Output: "HTTP/1.1 200 OK\nServer: nginx\n"},
		},
	}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 3}
	_, obs, err := loop.Run(context.Background(), "Test.", "Fetch example.com", []tools.Tool{
		{Name: "curl", Command: "curl", ShortDescription: "HTTP client", Parameters: []tools.Parameter{
			{Name: "url", Type: "string", Required: true, Format: "positional", Position: 0},
		}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(obs) != 1 || obs[0].Call.ID != "call_1" {
		t.Fatalf("expected native call_1, got %+v", obs)
	}
}

func TestLoopNoToolCalls(t *testing.T) {
	caller := &mockCaller{responses: []string{"No tools needed."}}
	exec := &mockExecutor{results: map[string]tools.ToolResult{}}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 3}
	final, obs, err := loop.Run(context.Background(), "Test.", "Task", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("expected no observations, got %d", len(obs))
	}
	if final != "No tools needed." {
		t.Fatalf("unexpected final: %s", final)
	}
}

func TestLoopMaxIterations(t *testing.T) {
	caller := &mockCaller{
		responses: []string{
			"<tool_call>{\"name\": \"nmap\", \"arguments\": {\"target\": \"x\"}}</tool_call>",
			"<tool_call>{\"name\": \"nmap\", \"arguments\": {\"target\": \"x\"}}</tool_call>",
			"<tool_call>{\"name\": \"nmap\", \"arguments\": {\"target\": \"x\"}}</tool_call>",
		},
	}
	exec := &mockExecutor{
		results: map[string]tools.ToolResult{
			"nmap": {Output: "open"},
		},
	}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 2}
	_, _, err := loop.Run(context.Background(), "Test.", "Task", []tools.Tool{
		{Name: "nmap", Command: "nmap", ShortDescription: "Port scanner", Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, Format: "positional", Position: 0},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "max iterations") {
		t.Fatalf("expected max iterations error, got %v", err)
	}
}

type recordingExecutor struct {
	calls []tools.ToolCall
}

func (r *recordingExecutor) Execute(ctx context.Context, call tools.ToolCall) (tools.ToolResult, error) {
	r.calls = append(r.calls, call)
	return tools.ToolResult{Name: call.Name, ID: call.ID, Output: "ok", ExitCode: 0}, nil
}

func intPtr(v int) *int { return &v }

func TestLoopValidationErrorAllowsRepair(t *testing.T) {
	caller := &mockCaller{responses: []string{
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":3}}</tool_call>`,
		`done`,
	}}
	exec := &recordingExecutor{}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 4, MaxRepairAttempts: 2}
	final, obs, err := loop.Run(context.Background(), "Test.", "Crawl", []tools.Tool{
		{Name: "katana", Command: "katana", ShortDescription: "Crawler", Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
			{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
		}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "done" {
		t.Fatalf("final = %q", final)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("expected one executed call, got %d", len(exec.calls))
	}
	if exec.calls[0].Args["depth"] != 3 {
		t.Fatalf("executed depth = %#v", exec.calls[0].Args["depth"])
	}
	if len(obs) != 2 {
		t.Fatalf("expected validation observation and execution observation, got %d", len(obs))
	}
	if !obs[0].Result.IsError || !strings.Contains(obs[0].Result.Error, "VALIDATION_ERROR") {
		t.Fatalf("first observation should be validation error: %+v", obs[0])
	}
}

func TestLoopStopsRepeatedInvalidCalls(t *testing.T) {
	caller := &mockCaller{responses: []string{
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
		`<tool_call>{"name":"katana","arguments":{"target":"https://example.com","depth":"d3"}}</tool_call>`,
	}}
	exec := &recordingExecutor{}
	loop := &Loop{Caller: caller, Executor: exec, MaxIter: 5, MaxRepairAttempts: 2}
	_, _, err := loop.Run(context.Background(), "Test.", "Crawl", []tools.Tool{
		{Name: "katana", Command: "katana", ShortDescription: "Crawler", Parameters: []tools.Parameter{
			{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
			{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "repeated invalid tool call") {
		t.Fatalf("expected repeated invalid error, got %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("invalid calls must not execute, got %d", len(exec.calls))
	}
}
