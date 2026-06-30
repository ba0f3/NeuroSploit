package types

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
}

// NewRunConfig creates a RunConfig with default values.
func NewRunConfig(target string) RunConfig {
	return RunConfig{
		Target:       target,
		Models:       []string{"anthropic:claude-opus-4-8"},
		VoteN:        3,
		Concurrency:  8,
		Pinned:       []string{},
	}
}
