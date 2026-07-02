package reconcache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func Slug(target string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	s = strings.TrimRight(s, "/")
	s = sanitizeRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		return "target"
	}
	return s
}

const staleAfter = 7 * 24 * time.Hour

type Manifest struct {
	Target    string   `json:"target"`
	Slug      string   `json:"slug"`
	CreatedAt string   `json:"created_at"`
	SourceRun string   `json:"source_run"`
	Tools     []string `json:"tools"`
	ReconHash string   `json:"recon_hash"`
}

type Bundle struct {
	Dir      string
	Slug     string
	Target   string
	Manifest Manifest
}

func ValidReconJSON(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return false
	}
	return json.Valid([]byte(s))
}

func LoadBundle(dir string) (*Bundle, error) {
	reconPath := filepath.Join(dir, "recon.json")
	reconBytes, err := os.ReadFile(reconPath)
	if err != nil {
		return nil, fmt.Errorf("recon.json: %w", err)
	}
	if !ValidReconJSON(string(reconBytes)) {
		return nil, fmt.Errorf("invalid recon.json in %s", dir)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	target := m.Target
	if target == "" {
		target = m.Slug
	}
	return &Bundle{Dir: dir, Slug: m.Slug, Target: target, Manifest: m}, nil
}

func (b *Bundle) CreatedTime() (time.Time, error) {
	return time.Parse(time.RFC3339, b.Manifest.CreatedAt)
}

func (b *Bundle) Age() time.Duration {
	t, err := b.CreatedTime()
	if err != nil {
		return 0
	}
	return time.Since(t)
}

func (b *Bundle) StaleWarning() bool { return b.Age() > staleAfter }

func (b *Bundle) SourceRunBase() string {
	return filepath.Base(b.Manifest.SourceRun)
}

func FormatAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
