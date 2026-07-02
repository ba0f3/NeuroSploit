package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// VoteRecord is one validator model's verdict on a candidate finding.
type VoteRecord struct {
	FindingTitle string `json:"finding_title"`
	Endpoint     string `json:"endpoint"`
	Model        string `json:"model"`
	Verdict      string `json:"verdict"`
	Reason       string `json:"reason,omitempty"`
}

func persistVotes(workdir string, records []VoteRecord) string {
	if workdir == "" || len(records) == 0 {
		return ""
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return ""
	}
	path := filepath.Join(workdir, "votes.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return ""
	}
	mdPath := filepath.Join(workdir, "votes.md")
	_ = os.WriteFile(mdPath, []byte(votesMD(records)), 0644)
	return path
}

func votesMD(records []VoteRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Vote panel\n\n%d validator response(s).\n", len(records))
	cur := ""
	for _, r := range records {
		key := r.FindingTitle + "|" + r.Endpoint
		if key != cur {
			cur = key
			fmt.Fprintf(&b, "\n## %s\n- endpoint: %s\n\n", r.FindingTitle, r.Endpoint)
		}
		fmt.Fprintf(&b, "- **%s**: %s", r.Model, r.Verdict)
		if r.Reason != "" {
			fmt.Fprintf(&b, " — %s", r.Reason)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func evidenceForVote(f types.Finding) string {
	ev := f.Evidence
	if len(ev) > voteEvidenceLimit {
		return ev[:voteEvidenceLimit] + "\n... [truncated for vote panel]"
	}
	return ev
}
