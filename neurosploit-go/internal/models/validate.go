package models

import (
	"fmt"
	"os"
	"strings"
)

// ValidateModelRef checks that one panel entry can run (API key or subscription CLI on PATH).
func ValidateModelRef(m ModelRef) error {
	if ImpliesSubscription(m.Provider) {
		bin := CLIBinaryFor(m.Provider)
		if bin == "" {
			return fmt.Errorf("%s: no subscription CLI for provider %q", m.Label(), m.Provider)
		}
		if !BinaryInPath(bin) {
			return fmt.Errorf("%s: %q not on PATH — install and log in to the CLI", m.Label(), bin)
		}
		return nil
	}
	p := ProviderFor(m.Provider)
	if p == nil {
		return fmt.Errorf("%s: unknown provider %q", m.Label(), m.Provider)
	}
	if p.Key == "ollama" || p.Key == "litellm" {
		return nil
	}
	if p.Key == "azure" && os.Getenv("AZURE_OPENAI_ENDPOINT") == "" {
		return fmt.Errorf("%s: set AZURE_OPENAI_ENDPOINT", m.Label())
	}
	if resolveKey(p) == "" {
		hint := p.EnvKey
		if p.Key == "gemini" {
			hint = fmt.Sprintf("%s (or GOOGLE_API_KEY)", p.EnvKey)
		}
		return fmt.Errorf("%s: no API key (%s)", m.Label(), hint)
	}
	return nil
}

// ValidatePanel ensures every model in the voting/failover panel is runnable before recon starts.
func ValidatePanel(refs []ModelRef) error {
	if len(refs) == 0 {
		return fmt.Errorf("no models configured — set at least one with --model")
	}
	seen := make(map[string]bool)
	var errs []string
	for _, m := range refs {
		label := m.Label()
		if seen[label] {
			continue
		}
		seen[label] = true
		if err := ValidateModelRef(m); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("model panel not ready — fix credentials before running:\n  - %s", strings.Join(errs, "\n  - "))
}
