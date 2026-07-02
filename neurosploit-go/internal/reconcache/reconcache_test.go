package reconcache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/reconcache"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func TestValidReconJSON(t *testing.T) {
	if reconcache.ValidReconJSON(`{}`) || reconcache.ValidReconJSON(``) {
		t.Fatal("empty recon should be invalid")
	}
	if !reconcache.ValidReconJSON(`{"endpoints":["http://example.com/"]}`) {
		t.Fatal("non-empty JSON should be valid")
	}
}

func TestLoadBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	recon := `{"tech":["asp.net"],"endpoints":["http://example.com/login.aspx"]}`
	if err := os.WriteFile(filepath.Join(dir, "recon.json"), []byte(recon), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"target":"http://example.com/","slug":"example.com","created_at":"2026-07-02T12:00:00Z","source_run":"runs/ns-test-example.com","tools":["httpx"],"recon_hash":"sha256:deadbeef"}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := reconcache.LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Slug != "example.com" || b.Target != "http://example.com/" {
		t.Fatalf("bundle: %+v", b)
	}
}

func TestPublishImportRoundTrip(t *testing.T) {
	cacheRoot := t.TempDir()
	dest := t.TempDir()
	recon := `{"endpoints":["http://example.com/"]}`
	toolLog := "## 1. httpx\n"
	b, err := reconcache.Publish(cacheRoot, "runs/ns-test-example.com", "http://example.com/", recon, toolLog, []string{"httpx"})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := reconcache.Import(b, dest); err != nil {
		t.Fatalf("Import: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "recon.json"))
	if err != nil || string(got) != recon {
		t.Fatalf("recon.json mismatch: %q err=%v", got, err)
	}
}

func TestFindBundle(t *testing.T) {
	cacheRoot := t.TempDir()
	if _, err := reconcache.FindBundle(cacheRoot, "example.com"); err == nil {
		t.Fatal("expected not found")
	}
	_, err := reconcache.Publish(cacheRoot, "runs/ns-1-example.com", "http://example.com/", `{"x":1}`, "", []string{"httpx"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := reconcache.FindBundle(cacheRoot, "example.com")
	if err != nil || b.Slug != "example.com" {
		t.Fatalf("FindBundle: %v %+v", err, b)
	}
}

func TestFindLatestRun(t *testing.T) {
	runsRoot := t.TempDir()
	slug := "example.com"
	oldDir := filepath.Join(runsRoot, "ns-1000-"+slug)
	newDir := filepath.Join(runsRoot, "ns-2000-"+slug)
	for _, d := range []string{oldDir, newDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "recon.json"), []byte(`{"endpoints":["http://example.com/"]}`), 0644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := reconcache.FindLatestRun(runsRoot, slug)
	if err != nil || b.Dir != newDir {
		t.Fatalf("want newest run %s got %v err=%v", newDir, b, err)
	}
}

func TestResolveNonTTYDefaultsReuse(t *testing.T) {
	cfg := types.RunConfig{Target: "http://example.com/"}
	p, err := reconcache.Resolve(cfg, &reconcache.Bundle{Slug: "example.com"}, false)
	if err != nil || p != types.ReconPolicyReuse {
		t.Fatalf("got %q err=%v", p, err)
	}
}

func TestResolveFlagNew(t *testing.T) {
	cfg := types.RunConfig{ReconPolicy: types.ReconPolicyNew}
	p, err := reconcache.Resolve(cfg, &reconcache.Bundle{}, false)
	if err != nil || p != types.ReconPolicyNew {
		t.Fatalf("got %q", p)
	}
}

func TestResolveReuseMissingBundle(t *testing.T) {
	cfg := types.RunConfig{ReconPolicy: types.ReconPolicyReuse, Target: "http://example.com/"}
	_, err := reconcache.Resolve(cfg, nil, false)
	if err == nil {
		t.Fatal("expected error")
	}
}
