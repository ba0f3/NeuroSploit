package belief

import (
	"math"
	"testing"
)

func TestNodeEntropy(t *testing.T) {
	if got := (Node{P: 0.5}).Entropy(); math.Abs(got-1.0) > 1e-6 {
		t.Errorf("Entropy for P=0.5 = %v, want 1.0", got)
	}
	if got := (Node{P: 0.001}).Entropy(); math.Abs(got-0.0) > 0.015 {
		t.Errorf("Entropy for P=0.001 = %v, want near 0", got)
	}
}

func TestWorldModelObserveAndSetKnown(t *testing.T) {
	wm := WorldModel{Nodes: make(map[string]Node)}
	wm.Add("x", KindVuln, "x", 0.5)

	before := wm.Nodes["x"]
	wm.Observe("x", true, 0.9)
	after := wm.Nodes["x"]
	if after.P <= before.P {
		t.Errorf("Observe did not increase P: before %v after %v", before.P, after.P)
	}
	if after.Obs != before.Obs+1 {
		t.Errorf("Observe did not increment Obs: before %d after %d", before.Obs, after.Obs)
	}

	if wm.IsConfident("x", 0.7, 0.4) {
		t.Error("expected x not to be confident before SetKnown")
	}

	prevObs := wm.Nodes["x"].Obs
	wm.SetKnown("x", true)
	if math.Abs(wm.Nodes["x"].P-0.98) > 0.01 {
		t.Errorf("SetKnown(true) P = %v, want ~0.98", wm.Nodes["x"].P)
	}
	if wm.Nodes["x"].Obs != prevObs+3 {
		t.Errorf("SetKnown(true) Obs = %d, want %d", wm.Nodes["x"].Obs, prevObs+3)
	}
	if !wm.IsConfident("x", 0.7, 0.4) {
		t.Error("expected x to be confident after SetKnown(true)")
	}
}

func TestWorldModelFrontier(t *testing.T) {
	wm := WorldModel{Nodes: make(map[string]Node)}
	wm.Add("a", KindVuln, "a", 0.5)  // high entropy
	wm.Add("b", KindHost, "b", 0.98) // low entropy
	wm.Add("c", KindVuln, "c", 0.02) // low entropy

	frontier := wm.Frontier(0.5)
	if len(frontier) != 1 || frontier[0].ID != "a" {
		t.Errorf("Frontier(0.5) = %v, want only node a", frontier)
	}

	wm.Add("d", KindVuln, "d", 0.3)
	frontier = wm.Frontier(0.5)
	if len(frontier) != 2 {
		t.Fatalf("Frontier(0.5) length = %d, want 2", len(frontier))
	}
	if frontier[0].Entropy() < frontier[1].Entropy() {
		t.Error("Frontier is not sorted by descending entropy")
	}
}

func TestWorldModelUncertainty(t *testing.T) {
	wm := WorldModel{Nodes: make(map[string]Node)}
	if got := wm.Uncertainty(KindNone); got != 1.0 {
		t.Errorf("Uncertainty of empty model = %v, want 1.0", got)
	}
	wm.Add("a", KindVuln, "a", 0.5)
	wm.Add("b", KindHost, "b", 0.5)
	if got := wm.Uncertainty(KindVuln); math.Abs(got-1.0) > 1e-6 {
		t.Errorf("Uncertainty(Vuln) = %v, want 1.0", got)
	}
	if got := wm.Uncertainty(KindNone); math.Abs(got-1.0) > 1e-6 {
		t.Errorf("Uncertainty(all) = %v, want 1.0", got)
	}
}
