package tools

import (
	"strings"
	"testing"
)

func TestValidateCallNormalizesHostOnlyTarget(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com/app?q=1"}, "https://example.com")
	if !res.Runnable {
		t.Fatalf("expected runnable, got issues: %+v", res.Issues)
	}
	if got := res.Args["target"]; got != "example.com" {
		t.Fatalf("target = %v want example.com", got)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Message, "converted URL to host") {
		t.Fatalf("expected normalization warning, got %+v", res.Warnings)
	}
}

func TestValidateCallRejectsOutOfScopeNormalization(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://other.example"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected not runnable: %+v", res)
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != "scope_mismatch" {
		t.Fatalf("unexpected issues: %+v", res.Issues)
	}
}

func TestValidateCallRejectsBadInteger(t *testing.T) {
	tool := Tool{Name: "katana", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
		{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com", "depth": "d3"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected validation failure")
	}
	if len(res.Issues) != 1 || res.Issues[0].Parameter != "depth" || res.Issues[0].Code != "invalid_integer" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}

func TestValidateCallConvertsNumericString(t *testing.T) {
	tool := Tool{Name: "katana", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "url"},
		{Name: "depth", Type: "int", Min: intPtr(1), Max: intPtr(10)},
	}}
	res := ValidateCall(tool, map[string]any{"target": "https://example.com", "depth": "3"}, "https://example.com")
	if !res.Runnable {
		t.Fatalf("expected runnable, got %+v", res.Issues)
	}
	if got := res.Args["depth"]; got != 3 {
		t.Fatalf("depth = %#v want 3", got)
	}
}

func TestValidateCallRejectsMissingFuzzMarker(t *testing.T) {
	tool := Tool{Name: "ffuf", Parameters: []Parameter{
		{Name: "url", Type: "string", Required: true, TargetFormat: "url_with_fuzz"},
	}}
	res := ValidateCall(tool, map[string]any{"url": "https://example.com/path"}, "https://example.com")
	if res.Runnable {
		t.Fatalf("expected missing FUZZ marker failure")
	}
	if len(res.Issues) != 1 || res.Issues[0].Code != "missing_fuzz_marker" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}

func TestValidateCallRejectsUnsafeAdditionalArgs(t *testing.T) {
	tool := Tool{Name: "nmap", Parameters: []Parameter{
		{Name: "target", Type: "string", Required: true, TargetFormat: "host_or_ip"},
		{Name: "additional_args", Type: "string", AllowShell: false, AllowedFlags: []string{"-T4"}},
	}}
	res := ValidateCall(tool, map[string]any{"target": "example.com", "additional_args": "-T4; rm -rf /"}, "example.com")
	if res.Runnable {
		t.Fatalf("expected unsafe additional_args failure")
	}
	if len(res.Issues) == 0 || res.Issues[0].Code != "unsafe_additional_args" {
		t.Fatalf("unexpected issue: %+v", res.Issues)
	}
}
