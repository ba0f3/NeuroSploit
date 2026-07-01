package types

import "strings"

// Finding represents a validated (or candidate) security finding.
type Finding struct {
	ID             string   `json:"id"`
	Agent          string   `json:"agent"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	CWE            string   `json:"cwe"`
	CVSS           string   `json:"cvss"`
	Endpoint       string   `json:"endpoint"`
	Payload        string   `json:"payload"`
	Evidence       string   `json:"evidence"`
	Impact         string   `json:"impact"`
	Remediation    string   `json:"remediation"`
	Confidence     float64  `json:"confidence"`
	Validated      bool     `json:"validated"`
	Votes          string   `json:"votes"`
	OWASP          string   `json:"owasp"`
	MITRE          string   `json:"mitre"`
	Stage          string   `json:"stage"`
	Exploitability string   `json:"exploitability"`
	BusinessImpact string   `json:"business_impact"`
	ChainsFrom     []string `json:"chains_from"`
}

// SeverityRank returns a numeric rank for severity strings (critical=4, high=3, medium=2, low=1).
func SeverityRank(severity string) int {
	s := strings.ToLower(severity)
	switch {
	case strings.HasPrefix(s, "crit"):
		return 4
	case strings.HasPrefix(s, "high"):
		return 3
	case strings.HasPrefix(s, "med"):
		return 2
	case strings.HasPrefix(s, "low"):
		return 1
	default:
		return 0
	}
}

// DefaultFinding returns a Finding with sensible zero values.
func DefaultFinding() Finding {
	return Finding{
		Severity:   "Info",
		ChainsFrom: []string{},
	}
}

// RunConfig configures a single engagement run.
type RunConfig struct {
	Target       string   `json:"target"`
	Models       []string `json:"models"`
	VoteN        int      `json:"vote_n"`
	Concurrency  int      `json:"concurrency"`
	MaxAgents    int      `json:"max_agents"`
	Offline      bool     `json:"offline"`
	Subscription bool     `json:"subscription"`
	Workdir      *string  `json:"workdir,omitempty"`
	RLPath       *string  `json:"rl_path,omitempty"`
	Verbose      bool     `json:"verbose"`
	Instructions *string  `json:"instructions,omitempty"`
	Auth         *string  `json:"auth,omitempty"`
	Repo         *string  `json:"repo,omitempty"`
	Pinned       []string `json:"pinned"`
	AutoTools    bool     `json:"auto_tools,omitempty"`
	Interactive  bool     `json:"interactive,omitempty"`
	ToolTimeout  int      `json:"tool_timeout,omitempty"`
	CLITimeout   int      `json:"cli_timeout,omitempty"`
	Playbook     string   `json:"playbook,omitempty"`
	Skills       []string `json:"skills,omitempty"`
	DisableTools []string `json:"disable_tools,omitempty"`
	AutoSkills   bool     `json:"auto_skills,omitempty"`
}

// NewRunConfig creates a RunConfig with default values.
func NewRunConfig(target string) RunConfig {
	return RunConfig{
		Target:      target,
		Models:      []string{"anthropic:claude-opus-4-8"},
		VoteN:       3,
		Concurrency: 8,
		AutoTools:   true,
		Pinned:      []string{},
	}
}
