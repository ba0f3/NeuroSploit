package tools

import (
	"fmt"
	"strings"
	"testing"
)

// sampleArgsForTool returns minimal args so BuildCommand succeeds for a recipe.
func sampleArgsForTool(tool Tool) map[string]any {
	args := map[string]any{}
	for _, p := range tool.Parameters {
		if p.Name == "additional_args" {
			continue
		}
		if p.Required || p.Default != nil {
			args[p.Name] = sampleValue(p)
		}
	}
	for _, p := range tool.Parameters {
		if p.Required {
			if _, ok := args[p.Name]; !ok {
				args[p.Name] = sampleValue(p)
			}
		}
	}
	return args
}

func sampleValue(p Parameter) any {
	switch strings.ToLower(p.Type) {
	case "bool", "boolean":
		return true
	case "int", "integer":
		if p.Default != nil {
			return p.Default
		}
		return 3
	default:
		if p.Default != nil {
			return p.Default
		}
		switch p.Name {
		case "url", "target":
			if strings.Contains(p.Description, "FUZZ") {
				return "https://example.com/FUZZ"
			}
			if strings.Contains(strings.ToLower(p.Description), "unc") {
				return "//host/share"
			}
			return "https://example.com"
		case "host":
			return "example.com"
		case "domain":
			return "example.com"
		case "protocol":
			return "smb"
		case "mode":
			return "dir"
		case "wordlist":
			return "/usr/share/wordlists/dirb/common.txt"
		case "record_type":
			return "A"
		case "command":
			return "id"
		case "templates":
			return "technologies"
		case "severity":
			return "critical,high"
		case "ports":
			return "80,443"
		default:
			return "example"
		}
	}
}

func validateToolParameters(t *testing.T, tool Tool) {
	t.Helper()
	seen := map[string]bool{}
	for _, p := range tool.Parameters {
		if p.Name == "" {
			t.Fatal("parameter with empty name")
		}
		if seen[p.Name] {
			t.Fatalf("duplicate parameter %q", p.Name)
		}
		seen[p.Name] = true

		switch p.Format {
		case "flag", "combined":
			if p.Flag == "" && p.Type != "bool" && p.Type != "boolean" {
				t.Fatalf("parameter %q: flag/combined format requires flag", p.Name)
			}
		case "positional", "":
			// positional defaults must not be multi-flag strings (nmap scan_type anti-pattern)
			if d, ok := p.Default.(string); ok && strings.Contains(d, " ") && strings.HasPrefix(strings.TrimSpace(d), "-") {
				t.Fatalf("parameter %q: positional default %q looks like multiple flags; use tool args instead", p.Name, d)
			}
		default:
			t.Fatalf("parameter %q: unknown format %q", p.Name, p.Format)
		}

		if p.Format == "combined" && p.Flag == "" {
			t.Fatalf("parameter %q: combined format requires flag prefix", p.Name)
		}
	}

	schema := tool.FunctionDefinition()
	fn, ok := schema["function"].(map[string]any)
	if !ok {
		t.Fatal("FunctionDefinition missing function block")
	}
	if fn["name"] != tool.Name {
		t.Fatalf("schema name = %v want %q", fn["name"], tool.Name)
	}
	params, ok := fn["parameters"].(map[string]any)
	if !ok {
		t.Fatal("FunctionDefinition missing parameters")
	}
	if params["additionalProperties"] != false {
		t.Fatal("schema must set additionalProperties false")
	}
}

func assertRequiredParamsFail(t *testing.T, tool Tool, full map[string]any) {
	t.Helper()
	for _, p := range tool.Parameters {
		if !p.Required || p.Default != nil {
			continue
		}
		trimmed := map[string]any{}
		for k, v := range full {
			if k != p.Name {
				trimmed[k] = v
			}
		}
		if _, err := BuildCommand(tool, trimmed); err == nil {
			t.Fatalf("BuildCommand should fail without required param %q", p.Name)
		}
	}
}

func assertArgvContains(t *testing.T, argv []string, want ...string) {
	t.Helper()
	joined := strings.Join(argv, " ")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("argv %q missing %q", joined, w)
		}
	}
}

func assertArgvNotContains(t *testing.T, argv []string, forbidden ...string) {
	t.Helper()
	joined := strings.Join(argv, " ")
	for _, f := range forbidden {
		if strings.Contains(joined, f) {
			t.Fatalf("argv %q must not contain %q", joined, f)
		}
	}
}

// toolArgvChecks are recipe-specific regressions (Kali httpx, nmap flags, etc.).
var toolArgvChecks = map[string]func(t *testing.T, argv []string){
	"httpx": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "https://example.com")
		assertArgvNotContains(t, argv, "-u ", " -u")
	},
	"nmap": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "nmap", "-sV", "-sC", "-Pn")
		for _, a := range argv {
			if strings.Contains(a, "-sV -sC") {
				t.Fatalf("nmap argv contains unsplit scan flags: %q", a)
			}
		}
	},
	"curl": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "curl", "https://example.com", "-X", "GET", "-L")
	},
	"gobuster": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "gobuster", "dir", "-u", "https://example.com")
	},
	"netexec": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "netexec", "smb", "example.com")
	},
	"dig": func(t *testing.T, argv []string) {
		assertArgvContains(t, argv, "dig", "example.com", "A")
	},
}

func TestAllToolRecipesParameters(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	reg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tools := reg.List()
	if len(tools) < 25 {
		t.Fatalf("expected 25 tool recipes, got %d", len(tools))
	}

	for _, tool := range tools {
		t.Run(tool.Name, func(t *testing.T) {
			validateToolParameters(t, tool)

			if tool.Command == "" {
				t.Fatal("empty command")
			}
			if tool.Timeout <= 0 {
				t.Fatalf("timeout = %v", tool.Timeout)
			}

			args := sampleArgsForTool(tool)
			argv, err := BuildCommand(tool, args)
			if err != nil {
				t.Fatalf("BuildCommand: %v (args=%v)", err, args)
			}
			if len(argv) < 1 || argv[0] != tool.Command {
				t.Fatalf("argv[0] = %q want command %q", argv[0], tool.Command)
			}

			// every required user-supplied value should appear in argv
			for _, p := range tool.Parameters {
				if p.Name == "additional_args" || p.Type == "bool" || p.Type == "boolean" {
					continue
				}
				if !p.Required && p.Default == nil {
					continue
				}
				val := fmt.Sprintf("%v", args[p.Name])
				if p.Format == "combined" && p.Flag != "" {
					val = p.Flag + val
				}
				if p.Required && !strings.Contains(strings.Join(argv, " "), val) {
					t.Fatalf("required value %q for param %q not found in argv: %q", val, p.Name, strings.Join(argv, " "))
				}
			}

			assertRequiredParamsFail(t, tool, args)

			if check, ok := toolArgvChecks[tool.Name]; ok {
				check(t, argv)
			}
		})
	}
}

func TestAllToolRecipesBuildWithDefaultsOnly(t *testing.T) {
	root := findRepoRoot()
	if root == "" {
		t.Skip("repo root not found")
	}
	reg, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range reg.List() {
		t.Run(tool.Name, func(t *testing.T) {
			// minimal args: only required fields without defaults
			minimal := map[string]any{}
			for _, p := range tool.Parameters {
				if p.Required {
					minimal[p.Name] = sampleValue(p)
				}
			}
			if len(minimal) == 0 {
				t.Skip("no required parameters")
			}
			argv, err := BuildCommand(tool, minimal)
			if err != nil {
				t.Fatalf("BuildCommand minimal: %v", err)
			}
			if argv[0] != tool.Command {
				t.Fatalf("argv[0] = %q", argv[0])
			}
		})
	}
}
