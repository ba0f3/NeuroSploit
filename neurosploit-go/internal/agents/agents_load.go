//go:build !embed_agents

package agents

import "path/filepath"

// Load reads the markdown agent library from <base>/agents_md/.
func Load(base string) Library {
	return loadLibraryFromRoot(filepath.Join(base, "agents_md"))
}
