package rl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// State is a lightweight reinforcement-learning reward store.
// Each agent carries a weight in [Wmin, Wmax]; validated findings reward it,
// idle runs decay it slightly. Weights bias agent ordering on future runs and
// persist to a JSON file so the harness gets sharper over time.
type State struct {
	Weights map[string]float64 `json:"weights"`
	Runs    uint64             `json:"runs"`
}

const (
	Alpha = 0.3
	Wmin  = 0.05
	Wmax  = 1.0
)

// Load reads an existing State from path. On any error it returns a zero
// State with a non-nil Weights map.
func Load(path string) State {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{Weights: make(map[string]float64)}
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{Weights: make(map[string]float64)}
	}
	return s
}

// Weight returns the stored weight for agent, defaulting to 0.5.
func (s *State) Weight(agent string) float64 {
	w, ok := s.Weights[agent]
	if !ok {
		return 0.5
	}
	return w
}

// Update applies a reward in [-1, 1] to the agent's weight.
func (s *State) Update(agent string, reward float64) {
	if s.Weights == nil {
		s.Weights = make(map[string]float64)
	}
	w := s.Weight(agent)
	s.Weights[agent] = clamp(w+Alpha*(reward-w), Wmin, Wmax)
}

// Save persists the state to path, creating parent directories as needed.
func (s *State) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// SeverityReward maps a finding severity to a reward value.
func SeverityReward(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 1.0
	case "high":
		return 0.7
	case "medium":
		return 0.4
	case "low":
		return 0.2
	case "info":
		return 0.05
	default:
		return 0.05
	}
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
