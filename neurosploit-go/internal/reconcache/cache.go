package reconcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func reconHash(recon string) string {
	sum := sha256.Sum256([]byte(recon))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Publish(cacheRoot, sourceRun, target, reconJSON, toolLog string, toolNames []string) (*Bundle, error) {
	if !ValidReconJSON(reconJSON) {
		return nil, fmt.Errorf("refusing to publish empty recon")
	}
	slug := Slug(target)
	dir := filepath.Join(cacheRoot, slug)
	if err := os.MkdirAll(filepath.Join(dir, "tools"), 0755); err != nil {
		return nil, err
	}
	m := Manifest{
		Target:    target,
		Slug:      slug,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		SourceRun: sourceRun,
		Tools:     toolNames,
		ReconHash: reconHash(reconJSON),
	}
	if err := os.WriteFile(filepath.Join(dir, "recon.json"), []byte(reconJSON), 0644); err != nil {
		return nil, err
	}
	if toolLog != "" {
		md := fmt.Sprintf("# Tool log — %s\n\n%s", target, toolLog)
		if err := os.WriteFile(filepath.Join(dir, "recon_tools.md"), []byte(md), 0644); err != nil {
			return nil, err
		}
	}
	if sourceRun != "" {
		_ = copyIter01Logs(filepath.Join(sourceRun, "tools"), filepath.Join(dir, "tools"))
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0644); err != nil {
		return nil, err
	}
	return LoadBundle(dir)
}

func copyIter01Logs(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "iter01-") {
			continue
		}
		_ = copyFile(filepath.Join(srcDir, e.Name()), filepath.Join(dstDir, e.Name()))
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func Import(b *Bundle, destWorkdir string) error {
	if b == nil {
		return fmt.Errorf("nil bundle")
	}
	if err := os.MkdirAll(filepath.Join(destWorkdir, "tools"), 0755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(b.Dir, "recon.json"), filepath.Join(destWorkdir, "recon.json")); err != nil {
		return err
	}
	toolsMD := filepath.Join(b.Dir, "recon_tools.md")
	if _, err := os.Stat(toolsMD); err == nil {
		_ = copyFile(toolsMD, filepath.Join(destWorkdir, "recon_tools.md"))
	}
	_ = copyIter01Logs(filepath.Join(b.Dir, "tools"), filepath.Join(destWorkdir, "tools"))
	if source := b.Manifest.SourceRun; source != "" {
		_ = copyIter01Logs(filepath.Join(source, "tools"), filepath.Join(destWorkdir, "tools"))
	}
	return nil
}

func ReadRecon(b *Bundle) (reconJSON, toolLog string, err error) {
	reconBytes, err := os.ReadFile(filepath.Join(b.Dir, "recon.json"))
	if err != nil {
		return "", "", err
	}
	reconJSON = string(reconBytes)
	if toolBytes, err := os.ReadFile(filepath.Join(b.Dir, "recon_tools.md")); err == nil {
		toolLog = string(toolBytes)
	}
	return reconJSON, toolLog, nil
}

func FindBundle(cacheRoot, slug string) (*Bundle, error) {
	dir := filepath.Join(cacheRoot, slug)
	b, err := LoadBundle(dir)
	if err != nil {
		return nil, fmt.Errorf("no recon cache for %s: %w", slug, err)
	}
	return b, nil
}

func modTimeRFC3339(dir string) string {
	fi, err := os.Stat(dir)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return fi.ModTime().UTC().Format(time.RFC3339)
}

func slugFromRunDir(runDir string) string {
	base := filepath.Base(runDir)
	parts := strings.SplitN(base, "-", 3)
	if len(parts) >= 3 {
		return parts[2]
	}
	return base
}

func BundleFromRun(runDir string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(runDir, "recon.json"))
	if err != nil {
		return nil, err
	}
	if !ValidReconJSON(string(raw)) {
		return nil, fmt.Errorf("invalid recon in %s", runDir)
	}
	slug := slugFromRunDir(runDir)
	m := Manifest{
		Slug:      slug,
		CreatedAt: modTimeRFC3339(runDir),
		SourceRun: runDir,
	}
	return &Bundle{Dir: runDir, Slug: slug, Manifest: m}, nil
}

func FindLatestRun(runsRoot, slug string) (*Bundle, error) {
	suffix := "-" + slug
	var best string
	var bestTS int64
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "ns-") || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		dir := filepath.Join(runsRoot, e.Name())
		if _, err := BundleFromRun(dir); err != nil {
			continue
		}
		parts := strings.SplitN(e.Name(), "-", 3)
		if len(parts) < 2 {
			continue
		}
		var ts int64
		_, _ = fmt.Sscanf(parts[1], "%d", &ts)
		if ts >= bestTS {
			bestTS = ts
			best = dir
		}
	}
	if best == "" {
		return nil, fmt.Errorf("no prior run for %s", slug)
	}
	return BundleFromRun(best)
}

func Discover(cacheRoot, runsRoot, slug string) (*Bundle, error) {
	if b, err := FindBundle(cacheRoot, slug); err == nil {
		return b, nil
	}
	return FindLatestRun(runsRoot, slug)
}

type RunEntry struct {
	Dir string
	Age time.Duration
}

func ListRuns(runsRoot, slug string, limit int) []RunEntry {
	suffix := "-" + slug
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return nil
	}
	type scored struct {
		entry RunEntry
		ts    int64
	}
	var found []scored
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "ns-") || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		dir := filepath.Join(runsRoot, e.Name())
		if _, err := BundleFromRun(dir); err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		var ts int64
		parts := strings.SplitN(e.Name(), "-", 3)
		if len(parts) >= 2 {
			_, _ = fmt.Sscanf(parts[1], "%d", &ts)
		}
		found = append(found, scored{
			entry: RunEntry{Dir: dir, Age: time.Since(fi.ModTime())},
			ts:    ts,
		})
	}
	for i := 0; i < len(found); i++ {
		for j := i + 1; j < len(found); j++ {
			if found[j].ts > found[i].ts {
				found[i], found[j] = found[j], found[i]
			}
		}
	}
	if limit <= 0 {
		limit = 10
	}
	var out []RunEntry
	for i, s := range found {
		if i >= limit {
			break
		}
		out = append(out, s.entry)
	}
	return out
}

func PublishFromRun(cacheRoot, runDir, target string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(runDir, "recon.json"))
	if err != nil {
		return nil, err
	}
	toolLog := ""
	if b, err := os.ReadFile(filepath.Join(runDir, "recon_tools.md")); err == nil {
		s := string(b)
		if idx := strings.Index(s, "\n\n"); idx >= 0 {
			toolLog = s[idx+2:]
		}
	}
	if target == "" {
		target = "http://" + slugFromRunDir(runDir) + "/"
	}
	return Publish(cacheRoot, runDir, target, string(raw), toolLog, nil)
}

func ClearCache(cacheRoot, slug string) error {
	return os.RemoveAll(filepath.Join(cacheRoot, slug))
}

func ListCached(cacheRoot string) ([]*Bundle, error) {
	entries, err := os.ReadDir(cacheRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Bundle
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := LoadBundle(filepath.Join(cacheRoot, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}
