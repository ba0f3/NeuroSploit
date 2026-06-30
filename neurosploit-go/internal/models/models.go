package models

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Provider exposes an OpenAI-compatible /chat/completions endpoint.
type Provider struct {
	Key     string
	Label   string
	BaseURL string
	EnvKey  string
	Kind    string
	Models  []string
}

// Providers returns the full model registry.
func Providers() []Provider {
	return []Provider{
		{Key: "anthropic", Label: "Anthropic Claude", BaseURL: "https://api.anthropic.com/v1", EnvKey: "ANTHROPIC_API_KEY", Kind: "cli",
			Models: []string{"claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"}},
		{Key: "openai", Label: "OpenAI (ChatGPT)", BaseURL: "https://api.openai.com/v1", EnvKey: "OPENAI_API_KEY", Kind: "cli",
			Models: []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex", "gpt-5.2", "gpt-5.1", "gpt-5.1-codex", "o4"}},
		{Key: "xai", Label: "xAI Grok", BaseURL: "https://api.x.ai/v1", EnvKey: "XAI_API_KEY", Kind: "cli",
			Models: []string{"grok-4", "grok-4-fast"}},
		{Key: "gemini", Label: "Google Gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", EnvKey: "GEMINI_API_KEY", Kind: "cli",
			Models: []string{"gemini-3-pro", "gemini-2.5-pro", "gemini-2.5-flash"}},
		{Key: "nvidia_nim", Label: "NVIDIA NIM", BaseURL: "https://integrate.api.nvidia.com/v1", EnvKey: "NVIDIA_NIM_API_KEY", Kind: "api",
			Models: []string{"nvidia/llama-3.3-nemotron-super-49b-v1", "deepseek-ai/deepseek-r1", "qwen/qwen2.5-coder-32b-instruct"}},
		{Key: "deepseek", Label: "DeepSeek", BaseURL: "https://api.deepseek.com/v1", EnvKey: "DEEPSEEK_API_KEY", Kind: "api",
			Models: []string{"deepseek-reasoner", "deepseek-chat"}},
		{Key: "mistral", Label: "Mistral", BaseURL: "https://api.mistral.ai/v1", EnvKey: "MISTRAL_API_KEY", Kind: "api",
			Models: []string{"mistral-large-latest", "codestral-latest"}},
		{Key: "qwen", Label: "Qwen (DashScope)", BaseURL: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", EnvKey: "DASHSCOPE_API_KEY", Kind: "api",
			Models: []string{"qwen-max", "qwen2.5-coder-32b-instruct", "qwq-plus"}},
		{Key: "groq", Label: "Groq", BaseURL: "https://api.groq.com/openai/v1", EnvKey: "GROQ_API_KEY", Kind: "api",
			Models: []string{"llama-3.3-70b-versatile", "qwen-2.5-coder-32b"}},
		{Key: "together", Label: "Together AI", BaseURL: "https://api.together.xyz/v1", EnvKey: "TOGETHER_API_KEY", Kind: "api",
			Models: []string{"Qwen/Qwen2.5-Coder-32B-Instruct", "deepseek-ai/DeepSeek-R1", "meta-llama/Llama-3.3-70B-Instruct-Turbo"}},
		{Key: "litellm", Label: "LiteLLM (proxy)", BaseURL: "http://localhost:4000/v1", EnvKey: "LITELLM_API_KEY", Kind: "api",
			Models: []string{"gpt-4o", "claude-3-7-sonnet", "gemini/gemini-2.5-pro"}},
		{Key: "openrouter", Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", EnvKey: "OPENROUTER_API_KEY", Kind: "api",
			Models: []string{"anthropic/claude-opus-4-8", "qwen/qwen-2.5-coder-32b-instruct", "deepseek/deepseek-v4-pro", "meta-llama/llama-3.3-70b-instruct"}},
		{Key: "azure", Label: "Azure OpenAI", BaseURL: "", EnvKey: "AZURE_OPENAI_API_KEY", Kind: "api",
			Models: []string{"gpt-4o", "gpt-4o-mini", "gpt-5.1", "o4-mini"}},
		{Key: "ollama", Label: "Ollama (local)", BaseURL: "http://localhost:11434/v1", EnvKey: "OLLAMA_API_KEY", Kind: "api",
			Models: []string{"qwen2.5-coder:32b", "qwq:32b", "deepseek-r1:32b", "llama3.3:70b"}},
		{Key: "cursor", Label: "Cursor Agent", BaseURL: "", EnvKey: "", Kind: "cli",
			Models: []string{"auto", "claude-4.6-opus-high", "gpt-5.3-codex", "gemini-3-flash"}},
	}
}

// ProviderFor returns the provider with the given key, or nil if unknown.
func ProviderFor(key string) *Provider {
	for _, p := range Providers() {
		if p.Key == key {
			p := p
			return &p
		}
	}
	return nil
}

func resolveKey(p *Provider) string {
	k := os.Getenv(p.EnvKey)
	if k == "" && p.Key == "gemini" {
		k = os.Getenv("GOOGLE_API_KEY")
	}
	return k
}

// ModelRef is a provider:model selection.
type ModelRef struct {
	Provider string
	Model    string
}

// ModelRefParse parses a "provider:model" string. Defaults provider to anthropic.
func ModelRefParse(s string) ModelRef {
	if i := strings.Index(s, ":"); i >= 0 {
		return ModelRef{Provider: s[:i], Model: s[i+1:]}
	}
	return ModelRef{Provider: "anthropic", Model: s}
}

// Label returns the full "provider:model" label.
func (m ModelRef) Label() string {
	return fmt.Sprintf("%s:%s", m.Provider, m.Model)
}

// ChatClient is an OpenAI-compatible chat client.
type ChatClient struct {
	http *http.Client
}

// NewChatClient creates a ChatClient.
func NewChatClient() ChatClient {
	return ChatClient{http: &http.Client{Timeout: 120 * time.Second}}
}

// Chat performs one HTTP chat completion.
func (c ChatClient) Chat(ctx context.Context, m ModelRef, system, user string) (string, error) {
	p := ProviderFor(m.Provider)
	if p == nil {
		return "", fmt.Errorf("unknown provider '%s'", m.Provider)
	}
	key := resolveKey(p)
	if key == "" && p.Key != "ollama" && p.Key != "litellm" {
		hint := p.EnvKey
		if p.Key == "gemini" {
			hint = fmt.Sprintf("%s (or GOOGLE_API_KEY)", p.EnvKey)
		}
		return "", fmt.Errorf("no API key (%s) for provider '%s'", hint, p.Key)
	}
	azure := p.Key == "azure"
	var url string
	if azure {
		endpoint := os.Getenv("AZURE_OPENAI_ENDPOINT")
		if endpoint == "" {
			return "", fmt.Errorf("set AZURE_OPENAI_ENDPOINT for the azure provider")
		}
		ver := os.Getenv("AZURE_OPENAI_API_VERSION")
		if ver == "" {
			ver = "2024-10-21"
		}
		url = fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
			strings.TrimRight(endpoint, "/"), m.Model, ver)
	} else {
		base := p.BaseURL
		switch p.Key {
		case "litellm":
			if b := os.Getenv("LITELLM_BASE_URL"); b != "" {
				base = b
			}
		case "ollama":
			if b := os.Getenv("OLLAMA_BASE_URL"); b != "" {
				base = b
			}
		}
		url = fmt.Sprintf("%s/chat/completions", strings.TrimRight(base, "/"))
	}
	body := map[string]interface{}{
		"model":       m.Model,
		"max_tokens":  4096,
		"temperature": 0.2,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		if azure {
			req.Header.Set("api-key", key)
		} else {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key))
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	text, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s returned %d: %s", p.Key, resp.StatusCode, truncate(string(text), 200))
	}
	var v map[string]interface{}
	if err := json.Unmarshal(text, &v); err != nil {
		return "", err
	}
	choices, ok := v["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	choice, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid choice shape")
	}
	message, ok := choice["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid message shape")
	}
	content, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("no content in response")
	}
	return content, nil
}

// ChatCLI completes via a locally-installed agentic CLI subscription.
func (c ChatClient) ChatCLI(ctx context.Context, label, provider, model, system, user, mcpConfig string, progress chan<- string) (string, error) {
	bin := CLIBinaryFor(provider)
	if bin == "" {
		return "", fmt.Errorf("no CLI/subscription backend for provider '%s'", provider)
	}
	prompt := system + "\n\n" + user
	if bin == "claude" {
		return chatClaudeStream(ctx, label, model, prompt, mcpConfig, progress)
	}
	if bin == "agent" || bin == "cursor-agent" {
		return chatCursorCLI(ctx, bin, model, prompt, mcpConfig)
	}
	args := []string{bin}
	switch bin {
	case "codex":
		args = append(args, "exec", "--model", model, "--dangerously-bypass-approvals-and-sandbox")
		if mcpConfig != "" {
			args = append(args, "--config", "mcp_config_file="+mcpConfig)
		}
		args = append(args, "-")
	case "gemini":
		args = append(args, "-m", model)
	case "grok":
		args = append(args, "--model", model)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(prompt)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn %s failed: %w", bin, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("%s: %w", bin, err)
		}
	case <-time.After(10 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("%s subscription CLI timed out after 600s", bin)
	}
	stdout := strings.TrimSpace(outBuf.String())
	stderr := errBuf.String()
	if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
		detail := stderr
		if detail == "" {
			detail = stdout
			if detail == "" {
				detail = "no output"
			}
		}
		return "", fmt.Errorf("%s subscription CLI exit %d: %s", bin, cmd.ProcessState.ExitCode(), truncate(detail, 240))
	}
	if stdout == "" {
		return "", fmt.Errorf("%s subscription CLI returned empty output", bin)
	}
	return stdout, nil
}

func chatClaudeStream(ctx context.Context, label, model, prompt, mcpConfig string, progress chan<- string) (string, error) {
	cmd := exec.CommandContext(ctx, "claude", "-p", "--model", model, "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions")
	cmd.Env = append(os.Environ(), "IS_SANDBOX=1")
	if mcpConfig != "" {
		cmd.Args = append(cmd.Args, "--mcp-config", mcpConfig)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stdin = strings.NewReader(prompt)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn claude failed: %w", err)
	}

	var result string
	var hadErr string
	emit := func(s string) {
		if progress != nil && s != "" {
			lbl := ""
			if label != "" {
				lbl = "@" + label + " "
			}
			select {
			case progress <- lbl + s:
			default:
			}
		}
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(stdoutPipe)
		for sc.Scan() {
			line := sc.Text()
			var v map[string]interface{}
			if err := json.Unmarshal([]byte(line), &v); err != nil {
				continue
			}
			typ, _ := v["type"].(string)
			switch typ {
			case "assistant":
				if msg, ok := v["message"].(map[string]interface{}); ok {
					if content, ok := msg["content"].([]interface{}); ok {
						for _, blk := range content {
							if b, ok := blk.(map[string]interface{}); ok {
								if t, _ := b["type"].(string); t == "text" {
									if txt, ok := b["text"].(string); ok {
										emit("ai: " + truncate(txt, 240))
									}
								}
							}
						}
					}
				}
			case "result":
				if r, ok := v["result"].(string); ok {
					result = r
				}
				if isErr, _ := v["is_error"].(bool); isErr {
					hadErr, _ = v["result"].(string)
				}
			}
		}
	}()

	select {
	case <-readDone:
	case <-time.After(15 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("claude stream timed out after 900s")
	}
	_ = cmd.Wait()
	if hadErr != "" && result == "" {
		return "", fmt.Errorf("claude: %s", truncate(hadErr, 240))
	}
	if result == "" {
		return "", fmt.Errorf("claude stream produced no result")
	}
	return result, nil
}

func chatCursorCLI(ctx context.Context, bin, model, prompt, mcpConfig string) (string, error) {
	args := []string{"-p", "--model", model, "--output-format", "text", "--trust"}
	if mcpConfig != "" {
		args = append(args, "--mcp-config", mcpConfig)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn %s failed: %w", bin, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("%s: %w: %s", bin, err, errBuf.String())
		}
	case <-time.After(10 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("%s timed out after 600s", bin)
	}
	stdout := strings.TrimSpace(outBuf.String())
	if stdout == "" {
		return "", fmt.Errorf("%s returned empty output", bin)
	}
	return stdout, nil
}

// CLIBinaryFor maps a provider to its local agentic CLI binary.
func CLIBinaryFor(provider string) string {
	switch provider {
	case "anthropic":
		return "claude"
	case "openai":
		return "codex"
	case "xai":
		return "grok"
	case "gemini":
		return "gemini"
	case "cursor":
		if BinaryInPath("agent") {
			return "agent"
		}
		return "cursor-agent"
	default:
		return ""
	}
}

// BinaryInPath reports whether an executable named `name` exists on PATH.
func BinaryInPath(name string) bool {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// InstalledCLIBackends lists the subscription CLI backends that are installed locally.
func InstalledCLIBackends() []string {
	var out []string
	for _, b := range []string{"claude", "codex", "grok", "gemini"} {
		if BinaryInPath(b) {
			out = append(out, b)
		}
	}
	return out
}

// MCPSupported reports whether the provider's CLI accepts a Playwright MCP config.
func MCPSupported(provider string) bool {
	return provider == "anthropic" || provider == "openai" || provider == "cursor"
}

// EnsurePlaywrightMCP best-effort pre-warms the Playwright MCP package.
func EnsurePlaywrightMCP() error {
	if !BinaryInPath("npx") {
		return fmt.Errorf("npx (Node.js) not found — install Node to use Playwright MCP")
	}
	cmd := exec.Command("npx", "-y", "@playwright/mcp@latest", "--help")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not provision @playwright/mcp via npx: %w", err)
	}
	return nil
}

// WriteMCPConfig writes an .mcp.json into dir and returns its path.
func WriteMCPConfig(dir string, extraServers string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	servers := map[string]interface{}{
		"playwright": map[string]interface{}{
			"command": "npx",
			"args":    []string{"-y", "@playwright/mcp@latest", "--headless", "--isolated"},
		},
	}
	if extraServers != "" {
		if data, err := os.ReadFile(extraServers); err == nil {
			var v map[string]interface{}
			if err := json.Unmarshal(data, &v); err == nil {
				add := v
				if mcp, ok := v["mcpServers"].(map[string]interface{}); ok {
					add = mcp
				}
				for k, val := range add {
					servers[k] = val
				}
			}
		}
	}
	cfg := map[string]interface{}{"mcpServers": servers}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
