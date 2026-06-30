package belief

import (
	"math"
	"sort"
)

// Kind describes what a belief node represents.
type Kind int

const (
	KindNone Kind = iota
	KindHost
	KindService
	KindVuln
	KindExploit
	KindCredential
)

const (
	entropyEpsilon = 1e-6
	obsRelEpsilon  = 1e-6
)

// Node is a single proposition with a probability of being true and an
// evidence count.
type Node struct {
	ID    string
	Kind  Kind
	Label string
	P     float64
	Obs   uint32
}

// Entropy returns the Shannon entropy in bits of the Bernoulli(P) belief.
func (n Node) Entropy() float64 {
	p := clamp(n.P, entropyEpsilon, 1.0-entropyEpsilon)
	return -(p*math.Log2(p) + (1.0-p)*math.Log2(1.0-p))
}

// Edge is a directed dependency between two belief nodes.
type Edge struct {
	From string
	To   string
	P    float64
}

// WorldModel is a property graph over the partially-observed target.
type WorldModel struct {
	Nodes         map[string]Node
	Edges         []Edge
	Deterministic bool
}

// Add seeds a node with a prior if it is not already present.
func (wm *WorldModel) Add(id string, kind Kind, label string, p float64) {
	if wm.Nodes == nil {
		wm.Nodes = make(map[string]Node)
	}
	if _, ok := wm.Nodes[id]; ok {
		return
	}
	wm.Nodes[id] = Node{
		ID:    id,
		Kind:  kind,
		Label: label,
		P:     clamp(p, 0.0, 1.0),
		Obs:   0,
	}
}

// Link appends a directed edge with probability clamped to [0,1].
func (wm *WorldModel) Link(from, to string, p float64) {
	wm.Edges = append(wm.Edges, Edge{
		From: from,
		To:   to,
		P:    clamp(p, 0.0, 1.0),
	})
}

// Observe updates a node's belief from one Bayesian observation.
func (wm *WorldModel) Observe(id string, positive bool, reliability float64) {
	node, ok := wm.Nodes[id]
	if !ok {
		return
	}
	r := clamp(reliability, 0.5+obsRelEpsilon, 1.0-obsRelEpsilon)
	p := clamp(node.P, entropyEpsilon, 1.0-entropyEpsilon)
	priorOdds := p / (1.0 - p)
	var lr float64
	if positive {
		lr = r / (1.0 - r)
	} else {
		lr = (1.0 - r) / r
	}
	postOdds := priorOdds * lr
	node.P = postOdds / (1.0 + postOdds)
	node.Obs++
	wm.Nodes[id] = node
}

// SetKnown collapses a node to near-certainty.
func (wm *WorldModel) SetKnown(id string, truth bool) {
	node, ok := wm.Nodes[id]
	if !ok {
		return
	}
	if truth {
		node.P = 0.98
	} else {
		node.P = 0.02
	}
	node.Obs += 3
	wm.Nodes[id] = node
}

// Uncertainty returns the mean entropy of nodes of the given kind, or of all
// nodes if kind is KindNone. Returns 1.0 when no matching nodes exist.
func (wm *WorldModel) Uncertainty(kind Kind) float64 {
	var sum float64
	var count int
	for _, n := range wm.Nodes {
		if kind != KindNone && n.Kind != kind {
			continue
		}
		sum += n.Entropy()
		count++
	}
	if count == 0 {
		return 1.0
	}
	return sum / float64(count)
}

// Frontier returns nodes with entropy above threshold, sorted by entropy
// descending.
func (wm *WorldModel) Frontier(threshold float64) []Node {
	out := make([]Node, 0, len(wm.Nodes))
	for _, n := range wm.Nodes {
		if n.Entropy() > threshold {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Entropy() > out[j].Entropy()
	})
	return out
}

// IsConfident reports whether a node exists, has P >= minP, and has entropy
// below maxEntropy.
func (wm *WorldModel) IsConfident(id string, minP, maxEntropy float64) bool {
	node, ok := wm.Nodes[id]
	if !ok {
		return false
	}
	return node.P >= minP && node.Entropy() <= maxEntropy
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
