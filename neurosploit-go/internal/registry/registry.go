package registry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

// Registry is an in-memory JSONL findings registry.
type Registry struct {
	path     string
	findings []types.Finding
}

// New creates a Registry optionally bound to a file path.
func New(path string) *Registry {
	return &Registry{path: path}
}

// Load reads findings from a JSONL file.
func (r *Registry) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var out []types.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var finding types.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}
		out = append(out, finding)
	}
	r.findings = out
	r.path = path
	return sc.Err()
}

// Save writes all findings as JSONL to the configured path.
func (r *Registry) Save(path string) error {
	if path == "" {
		path = r.path
	}
	if path == "" {
		return fmt.Errorf("no registry path set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)
	for _, finding := range r.findings {
		data, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

// Append adds a finding to the registry and optionally persists it.
func (r *Registry) Append(finding types.Finding, persist bool) error {
	r.findings = append(r.findings, finding)
	if persist && r.path != "" {
		return r.Save("")
	}
	return nil
}

// Findings returns a copy of the stored findings.
func (r *Registry) Findings() []types.Finding {
	out := make([]types.Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

// Dedupe removes findings for which keep returns false and rewrites the registry file.
func (r *Registry) Dedupe(keep func(types.Finding) bool) error {
	var kept []types.Finding
	for _, f := range r.findings {
		if keep(f) {
			kept = append(kept, f)
		}
	}
	r.findings = kept
	if r.path != "" {
		return r.Save("")
	}
	return nil
}

// UniqueFindings returns deduplicated findings by ID, merging vote tags.
func (r *Registry) UniqueFindings() []types.Finding {
	seen := make(map[string]types.Finding)
	for _, f := range r.findings {
		if existing, ok := seen[f.ID]; ok {
			existing.Votes = mergeVoteTags(existing.Votes, f.Votes)
			seen[f.ID] = existing
		} else {
			seen[f.ID] = f
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]types.Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, seen[id])
	}
	return out
}

// MergeVotes consolidates duplicate vote tags across all stored findings.
func (r *Registry) MergeVotes() {
	for i := range r.findings {
		r.findings[i].Votes = normalizeVoteTags(r.findings[i].Votes)
	}
}

func mergeVoteTags(a, b string) string {
	return normalizeVoteTags(a + " " + b)
}

func normalizeVoteTags(s string) string {
	seen := make(map[string]struct{})
	var out []string
	for _, part := range strings.Fields(strings.ReplaceAll(s, ",", " ")) {
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return strings.Join(out, " ")
}
