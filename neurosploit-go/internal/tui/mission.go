package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/engagement"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/pipeline"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type progressMsg string

type doneMsg struct {
	out pipeline.RunOutput
}

type findingRow struct {
	sev, title, endpoint string
}

type targetRow struct {
	host, state string
}

type model struct {
	base   string
	cfg    types.RunConfig
	mode   string
	mcp    bool
	target string
	models string

	phase    string
	started  time.Time
	feed     []string
	findings []findingRow
	targets  []targetRow

	tin, tout uint64
	cost      float64

	input        textinput.Model
	filterErrors bool
	done         bool
	paused       bool

	progress chan string
	cancel   context.CancelFunc
}

var (
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b5cf6")).Bold(true)
	headerStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

// Run starts the Mission Control bubbletea UI for an engagement.
func Run(base string, cfg types.RunConfig, mode string, mcp bool) error {
	m := newModel(base, cfg, mode, mcp)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func newModel(base string, cfg types.RunConfig, mode string, mcp bool) *model {
	host := cfg.Target
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	ti := textinput.New()
	ti.Placeholder = "summary · pause · errors · clear · quit"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 60

	return &model{
		base:     base,
		cfg:      cfg,
		mode:     mode,
		mcp:      mcp,
		target:   cfg.Target,
		models:   strings.Join(cfg.Models, ", "),
		phase:    "starting",
		started:  time.Now(),
		targets:  []targetRow{{host: host, state: "running"}},
		input:    ti,
		progress: make(chan string, 256),
	}
}

func (m *model) Init() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	return tea.Batch(
		m.listenProgress(),
		m.runEngagement(ctx),
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return t })
}

func (m *model) listenProgress() tea.Cmd {
	return func() tea.Msg {
		line, ok := <-m.progress
		if !ok {
			return doneMsg{}
		}
		return progressMsg(line)
	}
}

func (m *model) runEngagement(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		out := engagement.Execute(ctx, m.base, m.cfg, m.mode, m.mcp, nil, m.progress)
		close(m.progress)
		return doneMsg{out: out}
	}
}

func (m *model) ingest(line string) {
	low := strings.ToLower(line)
	switch {
	case strings.Contains(low, "recon"):
		m.phase = "recon"
	case strings.Contains(low, "planning") || strings.Contains(low, "selected"):
		m.phase = "planning"
	case strings.HasPrefix(low, "exploit") || strings.Contains(low, "launching agent"):
		m.phase = "exploiting"
	case strings.HasPrefix(low, "vote") || strings.Contains(low, "validating"):
		m.phase = "validating"
	case strings.HasPrefix(low, "chain"):
		m.phase = "chaining"
	case strings.Contains(low, "validated finding"):
		m.phase = "complete"
	}
	if rest, ok := strings.CutPrefix(line, "finding: "); ok {
		if b, ok := strings.CutPrefix(rest, "["); ok {
			if sev, tail, ok := strings.Cut(b, "]"); ok {
				title, ep, _ := strings.Cut(strings.TrimSpace(tail), " @ ")
				m.findings = append(m.findings, findingRow{sev: sev, title: title, endpoint: ep})
				m.noteTarget(ep)
			}
		}
		return
	}
	if strings.Contains(low, "in=") || strings.Contains(low, "out=") {
		for _, part := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(part, "in="); ok {
				var n uint64
				_, _ = fmt.Sscanf(v, "%d", &n)
				m.tin += n
			}
			if v, ok := strings.CutPrefix(part, "out="); ok {
				var n uint64
				_, _ = fmt.Sscanf(v, "%d", &n)
				m.tout += n
			}
			if v, ok := strings.CutPrefix(part, "cost=$"); ok {
				var f float64
				_, _ = fmt.Sscanf(v, "%f", &f)
				m.cost += f
			}
		}
	}
	isErr := strings.Contains(low, "fail") || strings.Contains(low, "error")
	if m.filterErrors && !isErr {
		return
	}
	m.feed = append(m.feed, line)
	if len(m.feed) > 500 {
		m.feed = m.feed[len(m.feed)-500:]
	}
}

func (m *model) noteTarget(endpoint string) {
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return
	}
	for _, t := range m.targets {
		if t.host == host {
			return
		}
	}
	m.targets = append(m.targets, targetRow{host: host, state: "testing"})
}

func (m *model) composer(cmd string) []string {
	c := strings.TrimSpace(strings.ToLower(cmd))
	switch c {
	case "", "help":
		return nil
	case "pause", "/pause", "stop", "/stop":
		m.paused = true
		if m.cancel != nil {
			m.cancel()
		}
		return []string{"pausing — finishing in-flight work"}
	case "errors", "/errors":
		m.filterErrors = !m.filterErrors
		return []string{fmt.Sprintf("filter errors: %v", m.filterErrors)}
	case "clear", "/clear":
		m.feed = nil
		return nil
	case "summary", "/summary", "findings", "/findings":
		return m.summary()
	case "quit", "/quit", "exit":
		m.done = true
		if m.cancel != nil {
			m.cancel()
		}
		return nil
	default:
		return []string{fmt.Sprintf("noted: %s", cmd)}
	}
}

func (m *model) summary() []string {
	counts := map[string]int{}
	for _, f := range m.findings {
		counts[f.sev]++
	}
	sev := "0"
	if len(counts) > 0 {
		parts := make([]string, 0, len(counts))
		for k, v := range counts {
			parts = append(parts, fmt.Sprintf("%s:%d", k, v))
		}
		sev = strings.Join(parts, " ")
	}
	out := []string{fmt.Sprintf("partial summary: %d finding(s) [%s] · phase %s", len(m.findings), sev, m.phase)}
	for i := len(m.findings) - 1; i >= 0 && len(out) < 6; i-- {
		f := m.findings[i]
		out = append(out, fmt.Sprintf("  • [%s] %s", f.sev, f.title))
	}
	return out
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.done && (msg.String() == "esc" || msg.String() == "ctrl+c") {
			return m, tea.Quit
		}
		switch msg.String() {
		case "ctrl+c", "esc":
			m.paused = true
			if m.cancel != nil {
				m.cancel()
			}
		case "enter":
			line := m.input.Value()
			m.input.SetValue("")
			for _, l := range m.composer(line) {
				m.feed = append(m.feed, l)
			}
			if m.done && (line == "quit" || line == "/quit" || line == "exit") {
				return m, tea.Quit
			}
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
	case progressMsg:
		m.ingest(string(msg))
		return m, m.listenProgress()
	case doneMsg:
		m.done = true
		m.phase = "complete"
		if len(m.targets) > 0 {
			m.targets[0].state = "done"
		}
		if len(msg.out.Findings) > 0 {
			m.feed = append(m.feed, fmt.Sprintf("%d validated finding(s)", len(msg.out.Findings)))
		}
		return m, nil
	case time.Time:
		return m, tickCmd()
	}
	return m, nil
}

func (m *model) View() string {
	elapsed := time.Since(m.started)
	header := accentStyle.Render("NeuroSploit") +
		fmt.Sprintf(" │ %s │ %s │ %s │ %02d:%02d │ %d findings │ in/out %d/%d $%.3f",
			m.target, m.mode, m.phase, int(elapsed.Minutes()), int(elapsed.Seconds())%60,
			len(m.findings), m.tin, m.tout, m.cost)
	if m.paused {
		header += " │ stopping"
	}
	header = headerStyle.Render("Mission Control\n" + header)

	feedTitle := "Activity"
	if m.filterErrors {
		feedTitle += " [errors]"
	}
	var feedBody strings.Builder
	start := 0
	if len(m.feed) > 18 {
		start = len(m.feed) - 18
	}
	for _, line := range m.feed[start:] {
		feedBody.WriteString(feedStyle(line))
		feedBody.WriteByte('\n')
	}
	feed := panelStyle.Width(52).Render(feedTitle + "\n" + feedBody.String())

	var findBody strings.Builder
	for i := len(m.findings) - 1; i >= 0 && findBody.Len() < 800; i-- {
		f := m.findings[i]
		findBody.WriteString(fmt.Sprintf("[%s] %s\n", f.sev, f.title))
	}
	findings := panelStyle.Width(34).Render(fmt.Sprintf("Findings (%d)\n%s", len(m.findings), findBody.String()))

	var tgtBody strings.Builder
	for _, t := range m.targets {
		tgtBody.WriteString(fmt.Sprintf("%s  %s\n", t.state, t.host))
	}
	targets := panelStyle.Width(34).Render("Targets\n" + tgtBody.String())

	right := lipgloss.JoinVertical(lipgloss.Left, findings, targets)
	body := lipgloss.JoinHorizontal(lipgloss.Top, feed, right)

	composerHint := "composer: summary · pause · errors · clear"
	if m.done {
		composerHint = "done — type quit or Esc to exit"
	}
	composer := panelStyle.Render(composerHint + "\n" + m.input.View())

	return lipgloss.JoinVertical(lipgloss.Left, header, body, composer)
}

func feedStyle(line string) string {
	low := strings.ToLower(line)
	switch {
	case strings.HasPrefix(line, "finding:"):
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#facc15")).Render(line)
	case strings.Contains(low, "fail") || strings.Contains(low, "error"):
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444")).Render(line)
	case strings.Contains(low, "recon") || strings.Contains(low, "vote") || strings.Contains(low, "chain"):
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#22d3ee")).Render(line)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")).Render(line)
	}
}
