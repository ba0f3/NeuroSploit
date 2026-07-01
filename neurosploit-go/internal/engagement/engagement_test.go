package engagement

import "testing"

func TestSanitizeTarget(t *testing.T) {
	cases := map[string]string{
		"http://testphp.vulnweb.com/":  "testphp.vulnweb.com",
		"https://ag.3qgoituongdi.com/": "ag.3qgoituongdi.com",
		"testphp.vulnweb.com/":         "testphp.vulnweb.com",
		"http://example.com///":        "example.com",
		"http://example.com/foo/":      "example.com_foo",
	}
	for in, want := range cases {
		if got := SanitizeTarget(in); got != want {
			t.Fatalf("SanitizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
