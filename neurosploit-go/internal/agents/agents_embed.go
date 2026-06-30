//go:build embed_agents

package agents

import (
	"embed"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed agentsdata/**/*
var agentsFS embed.FS

// Load reads the embedded agents_md library (base is ignored).
func Load(_ string) Library {
	root := "agentsdata"
	kindFor := map[string]string{
		"vulns": "vuln", "meta": "meta", "recon": "recon",
		"code": "code", "infra": "infra", "chains": "chain",
	}
	byKind := map[string][]Agent{}
	_ = fs.WalkDir(agentsFS, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 {
			return nil
		}
		kind, ok := kindFor[parts[0]]
		if !ok {
			return nil
		}
		text, err := agentsFS.ReadFile(path)
		if err != nil {
			return nil
		}
		name := strings.TrimSuffix(d.Name(), ".md")
		byKind[kind] = append(byKind[kind], parseAgentFile(name, kind, string(text)))
		return nil
	})
	return Library{
		Vulns:  sortAgents(byKind["vuln"]),
		Meta:   sortAgents(byKind["meta"]),
		Recon:  sortAgents(byKind["recon"]),
		Code:   sortAgents(byKind["code"]),
		Infra:  sortAgents(byKind["infra"]),
		Chains: sortAgents(byKind["chain"]),
	}
}

func sortAgents(in []Agent) []Agent {
	if len(in) == 0 {
		return nil
	}
	out := append([]Agent(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
