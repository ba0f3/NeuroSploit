package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func writef(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

func writel(out io.Writer, args ...any) {
	_, _ = fmt.Fprintln(out, args...)
}

// Prompt reads a line from r with the given label.
func Prompt(r *bufio.Reader, out io.Writer, label string) string {
	writef(out, "%s: ", label)
	if w, ok := out.(*bufio.Writer); ok {
		_ = w.Flush()
	}
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

// Select presents a numbered single-choice menu and returns the selected index, or -1.
func Select(r *bufio.Reader, out io.Writer, label string, items []string) int {
	if len(items) == 0 {
		return -1
	}
	writel(out, label)
	for i, item := range items {
		writef(out, "  %d) %s\n", i+1, item)
	}
	for {
		s := Prompt(r, out, "choice")
		if s == "" {
			return -1
		}
		n, err := strconv.Atoi(s)
		if err == nil && n >= 1 && n <= len(items) {
			return n - 1
		}
		writel(out, "invalid choice")
	}
}

// MultiSelect presents a numbered multi-choice menu and returns selected indices.
func MultiSelect(r *bufio.Reader, out io.Writer, label string, items []string) []int {
	if len(items) == 0 {
		return nil
	}
	writef(out, "%s (enter comma-separated numbers, e.g. 1,3)\n", label)
	for i, item := range items {
		writef(out, "  %d) %s\n", i+1, item)
	}
	s := Prompt(r, out, "choices")
	var outIdx []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil && n >= 1 && n <= len(items) {
			outIdx = append(outIdx, n-1)
		}
	}
	return outIdx
}

// Confirm asks a yes/no question.
func Confirm(r *bufio.Reader, out io.Writer, label string) bool {
	for {
		s := strings.ToLower(Prompt(r, out, label+" (y/n)"))
		if s == "y" || s == "yes" {
			return true
		}
		if s == "n" || s == "no" || s == "" {
			return false
		}
		writel(out, "please answer y/n")
	}
}

// Wizard runs a setup wizard and returns the target, models, and workdir.
func Wizard(r *bufio.Reader, out io.Writer) (target string, models []string, workdir string) {
	writel(out, "=== NeuroSploit Setup Wizard ===")
	target = Prompt(r, out, "Target URL")
	workdir = Prompt(r, out, "Work directory")
	if workdir == "" {
		workdir = "."
	}
	m := Prompt(r, out, "Models (comma-separated provider:model)")
	for _, part := range strings.Split(m, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			models = append(models, part)
		}
	}
	if len(models) == 0 {
		models = []string{"anthropic:claude-opus-4-8"}
	}
	return
}

// Stdio returns the standard input/output for convenience.
func Stdio() (io.Reader, io.Writer) {
	return os.Stdin, os.Stdout
}

// Display prints a title and body.
func Display(out io.Writer, title, body string) {
	writef(out, "\n--- %s ---\n%s\n", title, body)
}
