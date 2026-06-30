package tui

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestPrompt(t *testing.T) {
	in := strings.NewReader("hello\n")
	var out bytes.Buffer
	got := Prompt(bufio.NewReader(in), &out, "Name")
	if got != "hello" {
		t.Errorf("Prompt = %q", got)
	}
	if !strings.Contains(out.String(), "Name:") {
		t.Errorf("Prompt output missing label: %q", out.String())
	}
}

func TestSelect(t *testing.T) {
	in := strings.NewReader("2\n")
	var out bytes.Buffer
	idx := Select(bufio.NewReader(in), &out, "Pick", []string{"a", "b", "c"})
	if idx != 1 {
		t.Errorf("Select = %d", idx)
	}
}

func TestSelectInvalidThenValid(t *testing.T) {
	in := strings.NewReader("9\n1\n")
	var out bytes.Buffer
	idx := Select(bufio.NewReader(in), &out, "Pick", []string{"a", "b"})
	if idx != 0 {
		t.Errorf("Select = %d", idx)
	}
}

func TestMultiSelect(t *testing.T) {
	in := strings.NewReader("1,3\n")
	var out bytes.Buffer
	idx := MultiSelect(bufio.NewReader(in), &out, "Pick", []string{"a", "b", "c"})
	if len(idx) != 2 || idx[0] != 0 || idx[1] != 2 {
		t.Errorf("MultiSelect = %v", idx)
	}
}

func TestConfirm(t *testing.T) {
	in := strings.NewReader("y\n")
	var out bytes.Buffer
	if !Confirm(bufio.NewReader(in), &out, "Proceed") {
		t.Error("Confirm should be true")
	}
}

func TestWizard(t *testing.T) {
	in := strings.NewReader("http://x.com\n/tmp\nopenai:gpt-5.5\n")
	var out bytes.Buffer
	target, models, workdir := Wizard(bufio.NewReader(in), &out)
	if target != "http://x.com" || workdir != "/tmp" || models[0] != "openai:gpt-5.5" {
		t.Errorf("Wizard results unexpected: %s, %v, %s", target, models, workdir)
	}
}
