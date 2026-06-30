package pomdp

import (
	"strings"
	"testing"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
)

func TestDecideReconThenExploit(t *testing.T) {
	wm := &belief.WorldModel{}
	nodeID := "vuln1"
	wm.Add(nodeID, belief.KindVuln, "diffuse vuln", 0.5)

	pol := DefaultPolicy()

	action := Decide(wm, pol)
	if action.Type != "recon" {
		t.Fatalf("expected recon, got %q", action.Type)
	}
	if action.Node != nodeID {
		t.Fatalf("expected Node %q, got %q", nodeID, action.Node)
	}
	if action.V <= 0 {
		t.Fatalf("expected positive V, got %f", action.V)
	}

	wm.SetKnown(nodeID, true)
	action = Decide(wm, pol)
	if action.Type != "exploit" {
		t.Fatalf("expected exploit after SetKnown, got %q", action.Type)
	}
	if action.Node != nodeID {
		t.Fatalf("expected exploit Node %q, got %q", nodeID, action.Node)
	}
}

func TestDecideEmptyWorldModel(t *testing.T) {
	wm := &belief.WorldModel{}
	action := Decide(wm, DefaultPolicy())
	if action.Type != "stop" {
		t.Fatalf("expected stop on empty world model, got %q", action.Type)
	}
}

func TestMayAssert(t *testing.T) {
	wm := &belief.WorldModel{}
	nodeID := "vuln1"
	wm.Add(nodeID, belief.KindVuln, "diffuse vuln", 0.5)

	pol := DefaultPolicy()

	err := MayAssert(wm, nodeID, pol)
	if err == nil || !strings.Contains(err.Error(), "diffuse") {
		t.Fatalf("expected diffuse error, got %v", err)
	}

	wm.Add("lowP", belief.KindVuln, "low probability vuln", 0.1)
	err = MayAssert(wm, "lowP", pol)
	if err == nil {
		t.Fatalf("expected low probability error, got nil")
	}
	if !strings.Contains(err.Error(), "too low") && !strings.Contains(err.Error(), "low") {
		t.Fatalf("expected low probability error, got %v", err)
	}

	wm.SetKnown(nodeID, true)
	err = MayAssert(wm, nodeID, pol)
	if err != nil {
		t.Fatalf("expected nil error for confident node, got %v", err)
	}
}

func TestValueOfInformationMissingNode(t *testing.T) {
	wm := &belief.WorldModel{}
	if v := ValueOfInformation(wm, "missing"); v != 0 {
		t.Fatalf("expected 0 for missing node, got %f", v)
	}
}
