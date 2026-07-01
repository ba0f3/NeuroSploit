package repl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/creds"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/engagement"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pool"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/skills"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/tools"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"github.com/peterh/liner"
)

// Session holds interactive REPL configuration.
type Session struct {
	Base         string
	Models       []string
	Subscription bool
	MCP          bool
	VoteN        int
	MaxAgents    int
	Target       string
	Repo         string
	Auth         string
	Focus        string
	CredsPath    string
	Offline      bool

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	live    *RunLive
}

// RunLive tracks an in-flight engagement for /status and /results.
type RunLive struct {
	Target     string
	Mode       string
	Phase      string
	Started    time.Time
	Findings   []types.Finding
	Summary    [][2]string // sev, title
	Agents     int
	AgentsDone int
	Workdir    string
}

// NewSession creates a REPL session with defaults.
func NewSession() *Session {
	return &Session{
		Models:    []string{"anthropic:claude-opus-4-8"},
		VoteN:     3,
		MaxAgents: 5,
	}
}

// ProjDir returns <cwd>/.neurosploit and ensures it exists.
func ProjDir() string {
	cwd, _ := os.Getwd()
	dir := filepath.Join(cwd, ".neurosploit")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// Run starts the liner-based REPL (default when no subcommand is given).
func Run(base string) error {
	s := NewSession()
	s.Base = base
	line := liner.NewLiner()
	defer func() { _ = line.Close() }()
	line.SetCtrlCAborts(false)
	line.SetTabCompletionStyle(liner.TabPrints)
	line.SetCompleter(func(line string) []string {
		if strings.HasPrefix(line, "/") {
			var out []string
			for _, c := range commandList {
				if strings.HasPrefix(c, line) {
					out = append(out, c)
				}
			}
			return out
		}
		return nil
	})
	histPath := filepath.Join(ProjDir(), "history")
	if f, err := os.Open(histPath); err == nil {
		_, _ = line.ReadHistory(f)
		_ = f.Close()
	}
	defer func() {
		if f, err := os.Create(histPath); err == nil {
			_, _ = line.WriteHistory(f)
			_ = f.Close()
		}
	}()

	fmt.Println("NeuroSploit REPL — line editing enabled. Type /help for commands.")
	for {
		prompt, err := line.Prompt("ns> ")
		if err == liner.ErrPromptAborted {
			fmt.Println("^C")
			continue
		}
		if err == io.EOF {
			fmt.Println()
			return nil
		}
		if err != nil {
			return err
		}
		line.AppendHistory(prompt)
		prompt = strings.TrimSpace(prompt)
		if prompt == "" {
			continue
		}
		if err := s.handle(prompt, os.Stdout); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// RunReader is a test-friendly REPL without liner.
func (s *Session) RunReader(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	fmt.Fprintln(w, "NeuroSploit interactive REPL. Type /help for commands.")
	_ = w.Flush()
	for {
		fmt.Fprint(w, "ns> ")
		_ = w.Flush()
		line, err := r.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := s.handle(line, w); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		_ = w.Flush()
	}
}

func (s *Session) handle(line string, out io.Writer) error {
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "/help", "/?":
		fmt.Fprint(out, helpText)
	case "/show", "/config":
		cr := (*creds.Creds)(nil)
		if s.CredsPath != "" {
			cr = creds.Load(s.CredsPath)
		}
		mode, _ := engagement.DetectMode(s.Repo, s.Target, cr)
		if s.Repo != "" && s.Target == "" {
			mode = "whitebox"
		} else if s.Repo == "" && s.Target == "" {
			mode = ""
		}
		modeStr := "(set /target and/or /repo)"
		if mode != "" {
			modeStr = engagement.ModeLabel(mode)
		}
		fmt.Fprintf(out, "mode: %s\ntarget: %s\nrepo: %s\ncreds: %s\nmodels: %v\nsubscription: %v\nmcp: %v\nvote-n: %d\nmax-agents: %d\noffline: %v\n",
			modeStr, s.Target, s.Repo, s.CredsPath, s.Models, s.Subscription, s.MCP, s.VoteN, s.MaxAgents, s.Offline)
	case "/providers":
		for _, p := range models.Providers() {
			fmt.Fprintf(out, "%-12s %s\n", p.Key, p.Label)
		}
	case "/model":
		if len(args) == 0 {
			fmt.Fprintf(out, "models: %v\n", s.Models)
		} else {
			s.Models = args
			fmt.Fprintf(out, "models set to %v\n", s.Models)
		}
	case "/target":
		if len(args) == 0 {
			fmt.Fprintf(out, "target: %s\n", s.Target)
		} else {
			s.Target = args[0]
			fmt.Fprintf(out, "target set to %s\n", s.Target)
		}
	case "/repo":
		if len(args) > 0 {
			s.Repo = args[0]
			fmt.Fprintf(out, "repo set to %s\n", s.Repo)
		} else {
			fmt.Fprintf(out, "repo: %s\n", s.Repo)
		}
	case "/creds":
		if len(args) > 0 {
			s.CredsPath = args[0]
			fmt.Fprintf(out, "creds set to %s\n", s.CredsPath)
		} else {
			fmt.Fprintf(out, "creds: %s\n", s.CredsPath)
		}
	case "/auth":
		if len(args) > 0 {
			s.Auth = strings.Join(args, " ")
			fmt.Fprintln(out, "auth header set")
		} else {
			fmt.Fprintf(out, "auth: %s\n", s.Auth)
		}
	case "/focus":
		if len(args) > 0 {
			s.Focus = strings.Join(args, " ")
			fmt.Fprintf(out, "focus set to %s\n", s.Focus)
		} else {
			fmt.Fprintf(out, "focus: %s\n", s.Focus)
		}
	case "/offline":
		s.Offline = !s.Offline
		fmt.Fprintf(out, "offline: %v\n", s.Offline)
	case "/subscription", "/sub":
		s.Subscription = !s.Subscription
		fmt.Fprintf(out, "subscription: %v\n", s.Subscription)
	case "/mcp":
		s.MCP = !s.MCP
		fmt.Fprintf(out, "mcp: %v\n", s.MCP)
	case "/votes":
		if len(args) > 0 {
			_, _ = fmt.Sscanf(args[0], "%d", &s.VoteN)
		}
		fmt.Fprintf(out, "vote-n: %d\n", s.VoteN)
	case "/max-agents":
		if len(args) > 0 {
			_, _ = fmt.Sscanf(args[0], "%d", &s.MaxAgents)
		}
		fmt.Fprintf(out, "max-agents: %d\n", s.MaxAgents)
	case "/run":
		if s.Target == "" && s.Repo == "" {
			fmt.Fprintln(out, "set /target <url> and/or /repo <path> first")
			return nil
		}
		cr := (*creds.Creds)(nil)
		if s.CredsPath != "" {
			cr = creds.Load(s.CredsPath)
		}
		mode, err := engagement.DetectMode(s.Repo, s.Target, cr)
		if err != nil {
			fmt.Fprintln(out, err.Error())
			return nil
		}
		if s.Repo != "" && s.Target == "" {
			mode = "whitebox"
		}
		runTarget := s.Target
		if runTarget == "" {
			runTarget = s.Repo
		}
		s.mu.Lock()
		if s.running {
			s.mu.Unlock()
			fmt.Fprintln(out, "run already in progress")
			return nil
		}
		s.running = true
		s.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		s.live = &RunLive{Target: runTarget, Mode: engagement.ModeLabel(mode), Phase: "starting", Started: time.Now()}
		fmt.Fprintf(out, "starting %s against %s\n", engagement.ModeLabel(mode), runTarget)
		go s.backgroundRun(ctx, out, mode)
	case "/stop":
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		fmt.Fprintln(out, "run stopped")
	case "/status":
		s.mu.Lock()
		live := s.live
		running := s.running
		s.mu.Unlock()
		if running && live != nil {
			fmt.Fprintf(out, "running %s · phase %s · %d/%d agents · %d findings · %s\n",
				live.Target, live.Phase, live.AgentsDone, live.Agents, len(live.Findings), live.Started.Format(time.Kitchen))
		} else if live != nil && live.Workdir != "" {
			fmt.Fprintf(out, "idle · last run %s · %d findings · %s\n", live.Target, len(live.Findings), live.Workdir)
		} else {
			fmt.Fprintln(out, "idle")
		}
	case "/results", "/report":
		s.mu.Lock()
		live := s.live
		s.mu.Unlock()
		if live == nil || len(live.Findings) == 0 {
			fmt.Fprintln(out, "no findings yet")
			return nil
		}
		for _, f := range live.Findings {
			fmt.Fprintf(out, "[%s] %s — %s (%s)\n", f.Severity, f.Title, f.Endpoint, f.CWE)
		}
		if live.Workdir != "" {
			fmt.Fprintf(out, "workdir: %s\n", live.Workdir)
		}
	case "/quit", "/exit":
		if s.cancel != nil {
			s.cancel()
		}
		return io.EOF
	default:
		fmt.Fprintf(out, "unknown command: %s (type /help)\n", cmd)
	}
	return nil
}

func (s *Session) backgroundRun(ctx context.Context, out io.Writer, mode string) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	cfg := s.RunConfig()
	if s.Repo != "" {
		cfg.Repo = &s.Repo
	}
	if cfg.Target == "" {
		cfg.Target = s.Repo
	}
	_ = engagement.ApplyCreds(ctx, &cfg, s.CredsPath)

	mcp := s.MCP
	if mode == "whitebox" {
		mcp = false
	}
	if mode == "host" {
		mcp = false
	}

	progress := make(chan string, 128)
	go func() {
		for line := range progress {
			s.ingestLive(line)
			fmt.Fprintln(out, line)
		}
	}()

	var stub pipeline.PoolCaller
	if s.Offline {
		stub = &offlineStub{}
	}
	outRun := engagement.Execute(ctx, s.Base, cfg, mode, mcp, stub, progress)
	close(progress)

	s.mu.Lock()
	if s.live != nil {
		s.live.Findings = outRun.Findings
		s.live.Workdir = outRun.Workdir
		s.live.Phase = "complete"
	}
	s.mu.Unlock()

	fmt.Fprintf(out, "run complete — %d validated finding(s) · %s\n", len(outRun.Findings), outRun.Workdir)
}

func (s *Session) ingestLive(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return
	}
	low := strings.ToLower(line)
	if strings.Contains(low, "recon complete") {
		s.live.Phase = "recon"
	}
	if strings.Contains(low, "selected") && strings.Contains(low, "agent") {
		s.live.Phase = "planning"
	}
	if strings.HasPrefix(low, "exploit") || strings.HasPrefix(low, "test ") {
		s.live.Phase = "exploiting"
	}
	if strings.Contains(low, "validating") || strings.HasPrefix(low, "vote") {
		s.live.Phase = "validating"
	}
	if strings.HasPrefix(low, "chain") {
		s.live.Phase = "chaining"
	}
	if strings.Contains(low, "candidate(s)") && strings.HasPrefix(low, "exploit") {
		s.live.AgentsDone++
	}
	if rest, ok := strings.CutPrefix(line, "finding: "); ok {
		if b, ok := strings.CutPrefix(rest, "["); ok {
			if sev, tail, ok := strings.Cut(b, "]"); ok {
				title, _, _ := strings.Cut(strings.TrimSpace(tail), " @ ")
				s.live.Summary = append(s.live.Summary, [2]string{sev, title})
			}
		}
	}
	if j, ok := strings.CutPrefix(line, "finding_json: "); ok {
		var f types.Finding
		if json.Unmarshal([]byte(j), &f) == nil {
			s.live.Findings = append(s.live.Findings, f)
		}
	}
}

func (s *Session) RunConfig() types.RunConfig {
	cfg := types.NewRunConfig(s.Target)
	cfg.Models = s.Models
	cfg.MaxAgents = s.MaxAgents
	cfg.VoteN = s.VoteN
	cfg.Subscription = s.Subscription
	cfg.Offline = s.Offline
	if s.Focus != "" {
		cfg.Instructions = &s.Focus
	}
	if s.Repo != "" {
		cfg.Repo = &s.Repo
	}
	if s.Auth != "" {
		cfg.Auth = &s.Auth
	}
	cfg.Subscription = models.ApplyImpliedSubscription(cfg.Subscription, cfg.Models)
	return cfg
}

// HandleLine is a convenience for testing.
func (s *Session) HandleLine(line string, out io.Writer) error {
	return s.handle(line, out)
}

var commandList = []string{
	"/help", "/show", "/config", "/providers", "/model", "/target", "/repo", "/auth", "/creds", "/focus",
	"/offline", "/sub", "/subscription", "/mcp", "/votes", "/max-agents", "/run", "/stop",
	"/status", "/results", "/report", "/quit", "/exit",
}

const helpText = `
Available commands:
  /help, /?          Show this help
  /show, /config     Show current configuration
  /providers         List supported providers
  /model <m1> [m2..] Set model(s)
  /target <url>      Set live target (black-box or greybox with /repo)
  /repo <path>       Set repository path (white-box alone, greybox with /target)
  /creds <file.yaml> Credentials (jwt/login/ssh/windows)
  /auth <header>     Set auth header
  /focus <text>      Set focus instructions
  Modes: /target only = black-box · /repo only = white-box · both = greybox · /target IP + /creds ssh = host
  /offline           Toggle stub offline harness (no API keys)
  /sub               Toggle subscription mode
  /mcp               Toggle MCP
  /votes <n>         Set vote panel size
  /max-agents <n>    Set max agents
  /run               Start a run
  /stop              Stop current run
  /status            Show run status
  /results, /report  Show findings
  /quit, /exit       Quit the REPL
`

type offlineStub struct{}

func (offlineStub) SetProgress(chan<- string) {}

func (offlineStub) Complete(label string, task pool.Task, system, user string) (models.ModelRef, string, error) {
	ref := models.ModelRef{Provider: "offline", Model: "stub"}
	switch task {
	case pool.TaskRecon:
		return ref, `{}`, nil
	case pool.TaskSelect:
		return ref, `["sqli_error"]`, nil
	case pool.TaskExploit:
		return ref, `[{"title":"SQLi","severity":"Critical","cwe":"CWE-89","endpoint":"/x","evidence":"HTTP/1.1 200 OK Server: nginx","payload":"'","confidence":0.9}]`, nil
	default:
		return ref, "{}", nil
	}
}

func (offlineStub) Vote(system, user string, n int, skip string) (int, int) {
	if n < 1 {
		n = 1
	}
	return n, n
}

func (offlineStub) StopExploiting() bool { return false }

func (offlineStub) Tools() *tools.Registry   { return nil }
func (offlineStub) Executor() tools.Executor { return nil }
func (offlineStub) Skills() *skills.Library  { return nil }
func (offlineStub) CompleteWithTools(label string, task pool.Task, system, user string, tools []map[string]any) (models.ModelRef, string, error) {
	return offlineStub{}.Complete(label, task, system, user)
}
