# NeuroSploit Hardening: Tools, Skills, Playbooks, and Chains

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform NeuroSploit into a tool-calling, skill-aware, playbook-driven pentest harness that executes nmap/nuclei/nebula and enforces structured reasoning.

**Architecture:** Add a `tools/` runtime, a `skills/` library, a `playbooks/` engine, and a ReAct `toolloop`. Extend existing markdown agents with `Tools`/`Skills`/`OutputSchema` metadata. Keep backward compatibility with current agents.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` (new, justified), `mvdan.cc/sh/v3` (existing), stdlib.

**Global Constraints:**
- Do not modify `neurosploit-rs/`.
- Run commands from repo root so `agents_md/` is found.
- Run `go vet ./... && go test ./... -timeout 30s` before every commit.
- Do not add new dependencies beyond `gopkg.in/yaml.v3` without re-approval.
- Auto-execute allowlisted tools by default; add `--interactive` flag to prompt per command.
- Use native OpenAI tool schema when supported; fallback to prompt-tag parsing for local/unsupported models.

## Phase 1: Tool Runtime & Registry
- Add `gopkg.in/yaml.v3` to `go.mod`.
- Create `toolsdata/` and `internal/tools/`.
- Define `Tool`, `Parameter`, `Registry`, `Executor`, `ToolResult`.
- Seed 25+ tool recipes: `nmap`, `nuclei`, `nebula`, `httpx`, `katana`, `gau`, `ffuf`, `dirsearch`, `gobuster`, `whatweb`, `naabu`, `subfinder`, `amass`, `sqlmap`, `dalfox`, `nikto`, `wpscan`, `ssh`, `smbclient`, `netexec`, `curl`, `wget`, `whois`, `dig`, `rustscan`.
- Tests: loader, command builder, dangerous-command guard.

## Phase 2: Tool-Calling / ReAct Loop
- Create `internal/toolloop/`.
- Implement `Loop` with native `tool_calls` parsing and fallback `<tool_call>` tag parsing.
- Extend `models.ChatWithTools` and `pool.CompleteWithTools`.
- Tests: mock executor, loop iteration, fallback parsing.

## Phase 3: Skills System
- Create `skills_md/` and `internal/skills/`.
- `SKILL.md` format: YAML front matter + Markdown body.
- Seed 10 skills: `network_recon`, `web_recon`, `api_security`, `cve_scanning`, `ad_enum`, `cloud_metadata`, `auth_testing`, `file_upload_testing`, `sqli_testing`, `xss_testing`.
- Tests: loader, rendering, tool lookup.

## Phase 4: Playbook Engine
- Create `playbooks/` and `internal/playbooks/`.
- YAML format: name, description, tags, variables, phases (name, tools, agents, skills, post_analysis, condition).
- Run phases sequentially with state and condition evaluation.
- Tests: parsing, state passing, condition evaluation.

## Phase 5: Enhanced Prompts & Agent Metadata
- Rewrite `internal/pipeline/prompt.go`: universal validator, ReAct tool doctrine, mandatory output schema, evidence doctrine, severity doctrine.
- Extend `internal/agents/parse.go` to parse `## Tools`, `## Skills`, `## Output Schema`, `## Preconditions`.
- Add fields to `Agent`: `Tools`, `Skills`, `OutputSchema`, `Preconditions`.
- Update high-impact agents in `agents_md/` (recon, infra, top 20 vulns).
- Tests: metadata parsing, backward compatibility.

## Phase 6: Chain Engine
- Create `internal/chainengine/`.
- Replace `chainRound()` in `internal/pipeline/run.go` with a stateful engine.
- Chain stages have preconditions, tools, agents, success_condition.
- Stop early when a stage cannot be proven.
- Tests: mock chain, early stop.

## Phase 7: Orchestrator Integration
- Update `cmd/neurosploit/main.go`: add `--playbook`, `--skill`, `--tool-timeout`, `--auto-tools`, `--disable-tools`, `--interactive`, `--mcp-servers` flags.
- Update `engagement/engagement.go` to load tools, skills, playbooks and pass executor into pool.
- Update `pipeline/run.go`, `whitebox.go`, `greybox.go`, `host.go` to use toolloop when tools enabled.
- Tests: pipeline with mock tool executor.

## Phase 8: Testing, Docs, and CI
- Run full CI gate: `go vet ./...`, `go test ./... -timeout 30s`, `make build-release`, `goreleaser check`.
- Update `docs/PARITY.md`, `agents_md/REGISTRY.md`.
- Create `docs/SKILLS.md` and `docs/PLAYBOOKS.md`.
- Update `TUTORIAL.md` with `--playbook` and `--auto-tools` examples.

## Decisions (approved by user)
- Tool/playbook format: YAML with `gopkg.in/yaml.v3`.
- Tool execution: auto-execute allowlisted tools by default; `--interactive` prompts per command.
- Tool API: native OpenAI tools when supported; fallback prompt tags for local models.
- Agent migration: incremental; parser remains backward-compatible.
- Playbooks: optional; default pipeline also uses toolloop.
