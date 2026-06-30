package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/models"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func writef(w *bufio.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writel(w *bufio.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

func write(w *bufio.Writer, s string) {
	_, _ = fmt.Fprint(w, s)
}

func flush(w *bufio.Writer) {
	_ = w.Flush()
}

// Session holds interactive REPL configuration.
type Session struct {
	Models       []string
	Subscription bool
	MCP          bool
	VoteN        int
	MaxAgents    int
	Target       string
	Repo         string
	Auth         string
	Focus        string
	Offline      bool
	running      bool
	cancel       context.CancelFunc
}

// NewSession creates a REPL session with defaults.
func NewSession() *Session {
	return &Session{
		Models:    []string{"anthropic:claude-opus-4-8"},
		VoteN:     3,
		MaxAgents: 5,
	}
}

// Run starts the read-eval-print loop.
func (s *Session) Run(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer flush(w)

	writel(w, "NeuroSploit interactive REPL. Type /help for commands.")
	for {
		write(w, "ns> ")
		flush(w)
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
	}
}

func (s *Session) handle(line string, w *bufio.Writer) error {
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "/help", "/?":
		writel(w, strings.TrimSpace(helpText))
	case "/show", "/config":
		writef(w, "target: %s\nmodels: %v\nsubscription: %v\nmcp: %v\nvote-n: %d\nmax-agents: %d\noffline: %v\n",
			s.Target, s.Models, s.Subscription, s.MCP, s.VoteN, s.MaxAgents, s.Offline)
	case "/providers":
		for _, p := range models.Providers() {
			writef(w, "%-12s %s\n", p.Key, p.Label)
		}
	case "/model":
		if len(args) == 0 {
			writef(w, "models: %v\n", s.Models)
		} else {
			s.Models = args
			writef(w, "models set to %v\n", s.Models)
		}
	case "/target":
		if len(args) == 0 {
			writef(w, "target: %s\n", s.Target)
		} else {
			s.Target = args[0]
			writef(w, "target set to %s\n", s.Target)
		}
	case "/repo":
		if len(args) > 0 {
			s.Repo = args[0]
			writef(w, "repo set to %s\n", s.Repo)
		} else {
			writef(w, "repo: %s\n", s.Repo)
		}
	case "/auth":
		if len(args) > 0 {
			s.Auth = strings.Join(args, " ")
			writel(w, "auth header set")
		} else {
			writef(w, "auth: %s\n", s.Auth)
		}
	case "/focus":
		if len(args) > 0 {
			s.Focus = strings.Join(args, " ")
			writef(w, "focus set to %s\n", s.Focus)
		} else {
			writef(w, "focus: %s\n", s.Focus)
		}
	case "/offline":
		s.Offline = !s.Offline
		writef(w, "offline: %v\n", s.Offline)
	case "/subscription", "/sub":
		s.Subscription = !s.Subscription
		writef(w, "subscription: %v\n", s.Subscription)
	case "/mcp":
		s.MCP = !s.MCP
		writef(w, "mcp: %v\n", s.MCP)
	case "/votes":
		if len(args) > 0 {
			_, _ = fmt.Sscanf(args[0], "%d", &s.VoteN)
		}
		writef(w, "vote-n: %d\n", s.VoteN)
	case "/max-agents":
		if len(args) > 0 {
			_, _ = fmt.Sscanf(args[0], "%d", &s.MaxAgents)
		}
		writef(w, "max-agents: %d\n", s.MaxAgents)
	case "/run":
		if s.Target == "" {
			writel(w, "set a target first with /target")
			return nil
		}
		if s.running {
			writel(w, "run already in progress")
			return nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		s.running = true
		writef(w, "starting run against %s\n", s.Target)
		go s.backgroundRun(ctx, w)
	case "/stop":
		if s.cancel != nil {
			s.cancel()
		}
		s.running = false
		writel(w, "run stopped")
	case "/continue":
		writel(w, "continue: not implemented in this port")
	case "/status":
		if s.running {
			writef(w, "running against %s\n", s.Target)
		} else {
			writel(w, "idle")
		}
	case "/results", "/report":
		writel(w, "results: not implemented in this port")
	case "/quit", "/exit":
		return io.EOF
	default:
		writef(w, "unknown command: %s (type /help)\n", cmd)
	}
	return nil
}

func (s *Session) backgroundRun(ctx context.Context, w *bufio.Writer) {
	defer func() { s.running = false }()
	<-ctx.Done()
	writel(w, "run cancelled")
	flush(w)
}

func (s *Session) RunConfig() types.RunConfig {
	cfg := types.NewRunConfig(s.Target)
	cfg.Models = s.Models
	cfg.MaxAgents = s.MaxAgents
	cfg.VoteN = s.VoteN
	cfg.Offline = s.Offline
	cfg.Subscription = s.Subscription
	if s.Focus != "" {
		cfg.Instructions = &s.Focus
	}
	if s.Repo != "" {
		cfg.Repo = &s.Repo
	}
	if s.Auth != "" {
		cfg.Auth = &s.Auth
	}
	return cfg
}

const helpText = `
Available commands:
  /help, /?          Show this help
  /show, /config     Show current configuration
  /providers         List supported providers
  /model <m1> [m2..] Set model(s)
  /target <url>      Set target
  /repo <path>       Set repository path
  /auth <header>     Set auth header
  /focus <text>      Set focus instructions
  /offline           Toggle offline mode
  /sub               Toggle subscription mode
  /mcp               Toggle MCP
  /votes <n>         Set vote panel size
  /max-agents <n>    Set max agents
  /run               Start a run
  /stop              Stop current run
  /continue          Resume a paused run
  /status            Show run status
  /results, /report  Show results
  /quit, /exit       Quit the REPL
`

// HandleLine is a convenience for testing.
func (s *Session) HandleLine(line string, out io.Writer) error {
	w := bufio.NewWriter(out)
	defer flush(w)
	return s.handle(line, w)
}
