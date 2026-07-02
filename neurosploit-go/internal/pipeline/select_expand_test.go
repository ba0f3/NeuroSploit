package pipeline

import (
	"strings"
	"testing"
)

func TestExpandSelectedAgentsSQLiAndXSS(t *testing.T) {
	recon := `{"endpoints":["/Comments.aspx"],"params":[{"endpoint":"/Comments.aspx","params":["id"]}]}`
	names := expandSelectedAgents([]string{"sqli_error"}, recon)
	need := map[string]bool{"sqli_error": false, "sqli_blind": false, "sqli_union": false, "xss_stored": false}
	for _, n := range names {
		if _, ok := need[n]; ok {
			need[n] = true
		}
	}
	for n, ok := range need {
		if !ok {
			t.Fatalf("expandSelectedAgents missing %s in %v", n, names)
		}
	}
}

func TestInjectableURLs(t *testing.T) {
	recon := `{
		"endpoints":["/Comments.aspx","/ReadNews.aspx"],
		"params":[
			{"endpoint":"/Comments.aspx","params":["id"]},
			{"endpoint":"/ReadNews.aspx","params":["id","NewsAd"]}
		]
	}`
	urls := injectableURLs(recon, "http://testaspnet.vulnweb.com")
	if len(urls) < 2 {
		t.Fatalf("injectableURLs = %v, want at least 2", urls)
	}
	found := false
	for _, u := range urls {
		if strings.Contains(u, "Comments.aspx?id=1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing Comments.aspx probe URL in %v", urls)
	}
}

func TestParseSQLMapFinding(t *testing.T) {
	out := `Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1`
	f := parseSQLMapFinding(out, "http://x/Comments.aspx?id=1", "sqli_error", "/tmp/log")
	if f == nil {
		t.Fatal("expected sqlmap finding")
	}
	if f.Severity != "Critical" {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestParseSQLMapFindingNotInjectable(t *testing.T) {
	out := "all tested parameters do not appear to be injectable"
	if f := parseSQLMapFinding(out, "http://x/", "sqli_error", ""); f != nil {
		t.Fatalf("expected nil, got %+v", f)
	}
}
