package mcpbridge

import "testing"

func TestBaseCommandsPipeline(t *testing.T) {
	cmds, err := baseCommands("curl -s https://x | jq .")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 2 || cmds[0] != "curl" {
		t.Fatalf("got %v", cmds)
	}
}

func TestAllowlistDenyNonTTY(t *testing.T) {
	al := &Allowlist{Commands: []string{"echo"}}
	if al.Permits([]string{"curl"}, false) {
		t.Fatal("curl should be denied")
	}
}

func TestAllowlistPermitsListed(t *testing.T) {
	al := &Allowlist{Commands: []string{"echo"}}
	if !al.Permits([]string{"echo"}, false) {
		t.Fatal("echo should be permitted")
	}
}
