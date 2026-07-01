package agents

// Agent represents a markdown specialist/meta agent loaded from agents_md/.
type Agent struct {
	Name          string
	Title         string
	CWE           string
	Kind          string
	System        string
	User          string
	Tools         []string
	Skills        []string
	OutputSchema  string
	Preconditions []string
}

// Library is the loaded agents_md/ library split into six categories.
type Library struct {
	Vulns  []Agent
	Meta   []Agent
	Recon  []Agent
	Code   []Agent
	Infra  []Agent
	Chains []Agent
}

// Total returns the total number of agents across all six categories.
func (lib Library) Total() int {
	return len(lib.Vulns) + len(lib.Meta) + len(lib.Recon) +
		len(lib.Code) + len(lib.Infra) + len(lib.Chains)
}
