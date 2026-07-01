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
	"strconv"
	"strings"
	"sync"
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
			Models: []string{"auto", "composer-2.5", "claude-4.6-opus-high", "gpt-5.3-codex", "gemini-3-flash"}},
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
		ref := ModelRef{Provider: s[:i], Model: s[i+1:]}
		if ref.Provider == "agent" {
			ref.Provider = "cursor"
		}
		return ref
	}
	return ModelRef{Provider: "anthropic", Model: s}
}

// Label returns the full "provider:model" label.
func (m ModelRef) Label() string {
	return fmt.Sprintf("%s:%s", m.Provider, m.Model)
}

// ChatClient is an OpenAI-compatible chat client.
type ChatClient struct {
	http            *http.Client
	Verbose         bool
	CursorWorkspace string // repo root for cursor --workspace (subscription login scope)
}

// NewChatClient creates a ChatClient.
func NewChatClient() ChatClient {
	return ChatClient{http: &http.Client{Timeout: 120 * time.Second}}
}

func logCLI(verbose bool, cmd *exec.Cmd) {
	if !verbose {
		return
	}
	line := cmd.Path
	for _, a := range cmd.Args[1:] {
		if strings.Contains(a, "\n") || len(a) > 120 {
			line += " \"<redacted>\""
			continue
		}
		line += " " + strconv.Quote(a)
	}
	_, _ = fmt.Fprintf(os.Stderr, "cli> %s\n", line)
}

// ExtractChatContent returns assistant message text from a raw chat completion JSON
// response, or the input unchanged when it is not API JSON.
func ExtractChatContent(raw string) string {
	raw = strings.TrimSpace(raw)
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	choices, ok := v["choices"].([]any)
	if !ok || len(choices) == 0 {
		return raw
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return raw
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return raw
	}
	content, ok := message["content"].(string)
	if !ok || strings.TrimSpace(content) == "" {
		return raw
	}
	return content
}

// Chat performs one HTTP chat completion.

// ChatWithTools performs an HTTP chat completion with tool definitions and returns
// the raw API response so that callers can parse native tool_calls.
func (c ChatClient) ChatWithTools(ctx context.Context, m ModelRef, system, user string, tools []map[string]any) (string, error) {
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
	body := map[string]any{
		"model":       m.Model,
		"max_tokens":  4096,
		"temperature": 0.2,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	if len(tools) > 0 {
		body["tools"] = tools
		body["tool_choice"] = "auto"
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
	return string(text), nil
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
		return chatClaudeStream(ctx, label, model, prompt, mcpConfig, c.Verbose, progress)
	}
	if bin == "agent" || bin == "cursor-agent" {
		return chatCursorCLI(ctx, bin, label, model, prompt, mcpConfig, c.CursorWorkspace, c.Verbose, progress)
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
	logCLI(c.Verbose, cmd)
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

func chatClaudeStream(ctx context.Context, label, model, prompt, mcpConfig string, verbose bool, progress chan<- string) (string, error) {
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
	logCLI(verbose, cmd)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn claude failed: %w", err)
	}

	var result string
	var hadErr string
	emit := cliProgressEmitter(label, progress, verbose)

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		result, hadErr = consumeCLIStream(stdoutPipe, emit)
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

func cliProgressEmitter(label string, progress chan<- string, verbose bool) func(string) {
	return func(s string) {
		if progress == nil || s == "" {
			return
		}
		if strings.HasPrefix(s, "ai: ") && !verbose {
			return
		}
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

func consumeCLIStream(r io.Reader, emit func(string)) (result, hadErr string) {
	sc := bufio.NewScanner(r)
	// Cursor stream-json lines can be large (tool payloads).
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
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
						b, ok := blk.(map[string]interface{})
						if !ok {
							continue
						}
						switch t, _ := b["type"].(string); t {
						case "text":
							if txt, ok := b["text"].(string); ok {
								txt = strings.TrimSpace(txt)
								if txt != "" {
									emit("ai: " + truncate(txt, 240))
								}
							}
						case "tool_use":
							name, _ := b["name"].(string)
							var input map[string]interface{}
							if in, ok := b["input"].(map[string]interface{}); ok {
								input = in
							}
							emit(toolEvent(name, input))
						}
					}
				}
			}
		case "result":
			if r, ok := v["result"].(string); ok {
				result = r
			}
			ti, _ := jsonNumber(v, "usage", "input_tokens")
			to, _ := jsonNumber(v, "usage", "output_tokens")
			cost, _ := v["total_cost_usd"].(float64)
			if ti > 0 || to > 0 || cost > 0 {
				emit(fmt.Sprintf("tokens: in=%d out=%d cost=$%.4f", ti, to, cost))
			}
			if isErr, _ := v["is_error"].(bool); isErr {
				hadErr, _ = v["result"].(string)
			}
		}
	}
	return result, hadErr
}

func jsonNumber(v map[string]interface{}, keys ...string) (int64, bool) {
	cur := interface{}(v)
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return 0, false
		}
		cur = m[k]
	}
	switch n := cur.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func toolEvent(name string, input map[string]interface{}) string {
	s := func(k string) string {
		if input == nil {
			return ""
		}
		if v, ok := input[k].(string); ok {
			return v
		}
		return ""
	}
	switch name {
	case "Bash":
		c := s("command")
		danger := strings.Contains(c, "rm -rf") || strings.Contains(c, "mkfs") ||
			strings.Contains(c, ":(){") || strings.Contains(c, "dd if=") || strings.Contains(c, "> /dev/")
		if danger {
			return "danger: " + truncate(c, 200)
		}
		return "exec: " + truncate(c, 200)
	case "Read":
		return "read: " + s("file_path")
	case "Write", "Edit":
		return "edit: " + s("file_path")
	case "Grep":
		return "tool: grep " + truncate(s("pattern"), 80)
	case "Glob":
		return "tool: glob " + truncate(s("pattern"), 80)
	case "WebFetch":
		return "net: fetch " + s("url")
	default:
		if strings.Contains(strings.ToLower(name), "playwright") || strings.Contains(strings.ToLower(name), "browser") {
			url := s("url")
			if url != "" {
				return "net: browser " + name + " " + url
			}
			return "net: browser " + name
		}
		return "tool: " + name
	}
}

var cursorCLIMu sync.Mutex

func chatCursorCLI(ctx context.Context, bin, label, model, prompt, mcpConfig, workspace string, verbose bool, progress chan<- string) (string, error) {
	cursorCLIMu.Lock()
	defer cursorCLIMu.Unlock()

	path, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("spawn %s failed: %w", bin, err)
	}
	baseDir := ""
	if mcpConfig != "" {
		abs, err := filepath.Abs(mcpConfig)
		if err != nil {
			return "", fmt.Errorf("mcp config path: %w", err)
		}
		mcpConfig = abs
		baseDir = filepath.Dir(abs)
	} else {
		baseDir, _ = os.Getwd()
	}
	promptPath, err := writeCLIPromptFile(baseDir, prompt)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(promptPath) }()

	stream := progress != nil
	args, workdir, err := cursorCLIArgs(model, promptPath, mcpConfig, workspace, stream)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = workdir
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return "", fmt.Errorf("open stdin: %w", err)
	}
	defer stdin.Close()
	cmd.Stdin = stdin

	emit := cliProgressEmitter(label, progress, verbose)
	if label != "" {
		emit("notify: started")
	}

	logCLI(verbose, cmd)

	if stream {
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return "", err
		}
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		if err := cmd.Start(); err != nil {
			return "", fmt.Errorf("spawn %s failed: %w", bin, err)
		}
		readDone := make(chan struct{})
		var result, hadErr string
		go func() {
			defer close(readDone)
			result, hadErr = consumeCLIStream(stdoutPipe, emit)
		}()
		select {
		case <-readDone:
		case <-time.After(15 * time.Minute):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return "", fmt.Errorf("%s stream timed out after 900s", bin)
		}
		if err := cmd.Wait(); err != nil {
			detail := cursorCLIErrorDetail(errBuf.String(), "")
			return "", fmt.Errorf("%s: %w: %s", bin, err, detail)
		}
		if hadErr != "" && result == "" {
			return "", fmt.Errorf("%s: %s", bin, truncate(hadErr, 240))
		}
		if strings.TrimSpace(result) == "" {
			detail := cursorCLIErrorDetail(errBuf.String(), "")
			return "", fmt.Errorf("%s returned empty output: %s", bin, detail)
		}
		emit("notify: finished")
		return result, nil
	}

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
			detail := cursorCLIErrorDetail(errBuf.String(), outBuf.String())
			return "", fmt.Errorf("%s: %w: %s", bin, err, detail)
		}
	case <-time.After(10 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("%s timed out after 600s", bin)
	}
	result, err := parseCursorOutput(outBuf.String())
	if err != nil {
		return "", fmt.Errorf("%s: %w (%s)", bin, err, cursorCLIErrorDetail(errBuf.String(), outBuf.String()))
	}
	if strings.TrimSpace(result) == "" {
		detail := cursorCLIErrorDetail(errBuf.String(), outBuf.String())
		return "", fmt.Errorf("%s returned empty output: %s", bin, detail)
	}
	return result, nil
}

// writeCLIPromptFile stores agent instructions on disk so the Cursor CLI can read
// them without embedding untrusted content in argv (avoids injection and arg limits).
func writeCLIPromptFile(dir, prompt string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".ns-prompt-*.md")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.WriteString(prompt); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// cursorCLIArgs builds headless Cursor Agent CLI flags. The only argv prompt is a
// short meta-instruction pointing at a prompt file; agent content is never argv.
func cursorCLIArgs(model, promptPath, mcpConfig, workspace string, stream bool) (args []string, workdir string, err error) {
	absPrompt, err := filepath.Abs(promptPath)
	if err != nil {
		return nil, "", fmt.Errorf("prompt path: %w", err)
	}
	workdir = filepath.Dir(absPrompt)
	ws := strings.TrimSpace(workspace)
	if ws == "" {
		ws = workdir
	} else if abs, err := filepath.Abs(ws); err == nil {
		ws = abs
	}
	format := "text"
	if stream {
		format = "stream-json"
	}
	args = []string{"-p", "--model", model, "--output-format", format, "--trust", "--force", "--workspace", ws}
	if mcpConfig != "" {
		args = append(args, "--approve-mcps")
	}
	meta := cursorMetaPrompt(absPrompt)
	args = append(args, meta)
	return args, workdir, nil
}

func cursorMetaPrompt(promptPath string) string {
	abs, _ := filepath.Abs(promptPath)
	return fmt.Sprintf(
		"Read and follow all instructions in the file %s. Reply exactly as specified in that file.",
		abs,
	)
}

func cursorCLIErrorDetail(stderr, stdout string) string {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = strings.TrimSpace(stdout)
	}
	if detail == "" {
		return "no output (try `agent update`; cursor headless needs a single serial invocation per workspace)"
	}
	return truncate(detail, 240)
}

// UsesCursorCLI reports whether any candidate routes through the Cursor agent binary.
func UsesCursorCLI(refs []ModelRef) bool {
	for _, m := range refs {
		if m.Provider == "cursor" || m.Provider == "agent" {
			return true
		}
	}
	return false
}

// SubscriptionConcurrency returns the pool/exploit concurrency cap for subscription CLIs.
func SubscriptionConcurrency(refs []ModelRef, requested int) int {
	if requested < 1 {
		requested = 1
	}
	if UsesCursorCLI(refs) {
		return 1
	}
	if requested > 3 {
		return 3
	}
	return requested
}

func parseCursorOutput(stdout string) (string, error) {
	raw := strings.TrimSpace(stdout)
	if raw == "" {
		return "", fmt.Errorf("empty stdout")
	}
	var v struct {
		Result  string `json:"result"`
		IsError bool   `json:"is_error"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw, nil
	}
	if v.IsError {
		msg := strings.TrimSpace(v.Error)
		if msg == "" {
			msg = strings.TrimSpace(v.Result)
		}
		if msg == "" {
			msg = "agent reported is_error"
		}
		return "", fmt.Errorf("%s", msg)
	}
	if strings.TrimSpace(v.Result) != "" {
		return strings.TrimSpace(v.Result), nil
	}
	return raw, nil
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
	case "cursor", "agent":
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
func EnsurePlaywrightMCP(verbose bool) error {
	if !BinaryInPath("npx") {
		return fmt.Errorf("npx (Node.js) not found — install Node to use Playwright MCP")
	}
	cmd := exec.Command("npx", "-y", "@playwright/mcp@latest", "--help")
	cmd.Stdout = nil
	cmd.Stderr = nil
	logCLI(verbose, cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not provision @playwright/mcp via npx: %w", err)
	}
	return nil
}

// WriteMCPConfig writes Claude/Codex .mcp.json into dir and returns its path.
func WriteMCPConfig(dir string, extraServers string) (string, error) {
	data, err := marshalMCPConfig(extraServers)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// WriteCursorMCPConfig writes workspace/.cursor/mcp.json for the Cursor agent CLI.
func WriteCursorMCPConfig(workspace string, extraServers string) (string, error) {
	data, err := marshalMCPConfig(extraServers)
	if err != nil {
		return "", err
	}
	cursorDir := filepath.Join(workspace, ".cursor")
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(cursorDir, "mcp.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

func marshalMCPConfig(extraServers string) ([]byte, error) {
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
	return json.MarshalIndent(cfg, "", "  ")
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
