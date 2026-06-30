package hygiene

import (
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

func testFinding(title, sev, cwe, ep, ev, payload string) types.Finding {
	x := types.DefaultFinding()
	x.Title = title
	x.Severity = sev
	x.CWE = cwe
	x.Endpoint = ep
	x.Evidence = ev
	x.Payload = payload
	return x
}

func TestUnprovenHighIsCapped(t *testing.T) {
	v := []types.Finding{testFinding("Flooding DoS", "High", "CWE-770", "https://a/x", "could overload", "")}
	notes := Calibrate(&v)
	if v[0].Severity != "Medium" {
		t.Errorf("expected severity Medium, got %s", v[0].Severity)
	}
	if len(notes) != 1 {
		t.Errorf("expected 1 note, got %d", len(notes))
	}
}

func TestProvenHighIsKept(t *testing.T) {
	v := []types.Finding{testFinding("SQLi", "High", "CWE-89", "https://a/x",
		"id=1' UNION SELECT version()-- returned 8.0.32 in the response body, proving injection", "1' OR '1'='1")}
	Calibrate(&v)
	if v[0].Severity != "High" {
		t.Errorf("expected severity High, got %s", v[0].Severity)
	}
}

func TestExposureWithoutExploitFlagged(t *testing.T) {
	v := []types.Finding{testFinding("Information Disclosure - .git exposed", "Low", "CWE-527", "https://a/.git", "leaked", "")}
	if len(DepthAudit(v)) != 1 {
		t.Errorf("expected 1 depth note, got %d", len(DepthAudit(v)))
	}
}

func TestExposureWithExploitOnSameHostNotFlagged(t *testing.T) {
	v := []types.Finding{
		testFinding("Information Disclosure - banner", "Low", "CWE-200", "https://a/x", "Server: IIS", ""),
		testFinding("SQL Injection", "High", "CWE-89", "https://a/login", "dumped users", "1'--"),
	}
	if len(DepthAudit(v)) != 0 {
		t.Errorf("expected 0 depth notes, got %d", len(DepthAudit(v)))
	}
}

func TestCalibrateVietnameseWeasel(t *testing.T) {
	v := []types.Finding{testFinding("DoS", "High", "CWE-770", "https://a/x", "có thể gây quá tải", "")}
	notes := Calibrate(&v)
	if v[0].Severity != "Medium" {
		t.Errorf("severity = %s", v[0].Severity)
	}
	if len(notes) == 0 {
		t.Fatal("expected calibration note")
	}
}
