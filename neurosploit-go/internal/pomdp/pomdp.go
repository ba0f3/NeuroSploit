package pomdp

import (
	"errors"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/belief"
)

// Action represents the planner's recommendation.
type Action struct {
	Type string
	Node string
	V    float64
}

// Policy holds tunable decision thresholds.
type Policy struct {
	ExploreEntropy    float64
	AssertMinP        float64
	AssertMaxEntropy  float64
}

// DefaultPolicy returns the standard decision thresholds.
func DefaultPolicy() Policy {
	return Policy{
		ExploreEntropy:   0.6,
		AssertMinP:       0.7,
		AssertMaxEntropy: 0.4,
	}
}

// ValueOfInformation returns the entropy-weighted relevance of a node.
func ValueOfInformation(wm *belief.WorldModel, nodeID string) float64 {
	node, ok := wm.Nodes[nodeID]
	if !ok {
		return 0.0
	}
	var weight float64
	switch node.Kind {
	case belief.KindExploit, belief.KindCredential:
		weight = 1.0
	case belief.KindVuln:
		weight = 0.8
	case belief.KindService, belief.KindHost:
		weight = 0.5
	default:
		weight = 0.0
	}
	return weight * node.Entropy()
}

// Decide recommends the next action given the current belief and policy.
func Decide(wm *belief.WorldModel, pol Policy) Action {
	bestRecon := bestReconAction(wm)
	bestExploit := bestExploitAction(wm, pol)

	if bestRecon.V >= bestExploit.V && bestRecon.V > (1.0-pol.ExploreEntropy) {
		return Action{Type: "recon", Node: bestRecon.Node, V: bestRecon.V}
	}
	if bestExploit.V > 0.0 {
		return Action{Type: "exploit", Node: bestExploit.Node, V: bestExploit.V}
	}
	return Action{Type: "stop"}
}

func bestReconAction(wm *belief.WorldModel) Action {
	var best Action
	for id := range wm.Nodes {
		v := ValueOfInformation(wm, id)
		if v > best.V {
			best = Action{Node: id, V: v}
		}
	}
	return best
}

func bestExploitAction(wm *belief.WorldModel, pol Policy) Action {
	var best Action
	for _, node := range wm.Nodes {
		switch node.Kind {
		case belief.KindExploit, belief.KindVuln, belief.KindCredential:
			var v float64
			if node.Entropy() <= pol.AssertMaxEntropy {
				v = node.P
			}
			if v > best.V {
				best = Action{Node: node.ID, V: v}
			}
		}
	}
	return best
}

// MayAssert verifies that a node is confident enough to be asserted.
func MayAssert(wm *belief.WorldModel, nodeID string, pol Policy) error {
	node, ok := wm.Nodes[nodeID]
	if !ok {
		return errors.New("no belief state for node " + nodeID)
	}
	if node.Entropy() > pol.AssertMaxEntropy {
		return errors.New("node " + nodeID + " is too diffuse to assert")
	}
	if node.P < pol.AssertMinP {
		return errors.New("node " + nodeID + " probability is too low to assert")
	}
	return nil
}
