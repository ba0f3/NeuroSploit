<h1 align="center">🧠 NeuroSploit v3.5.4</h1>

<p align="center">
  <a href="https://github.com/JoasASantos/NeuroSploit/stargazers"><img src="https://img.shields.io/github/stars/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=8b5cf6" alt="Stars"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/network/members"><img src="https://img.shields.io/github/forks/JoasASantos/NeuroSploit?style=for-the-badge&logo=github&color=a855f7" alt="Forks"></a>
  <a href="https://github.com/JoasASantos/NeuroSploit/issues"><img src="https://img.shields.io/github/issues/JoasASantos/NeuroSploit?style=for-the-badge&color=22d3ee" alt="Issues"></a>
  <img src="https://img.shields.io/github/last-commit/JoasASantos/NeuroSploit?style=for-the-badge&color=34d399" alt="Last commit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.5.4-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/MD%20Agents-329-red?style=flat-square">
  <img src="https://img.shields.io/badge/Models-12%20providers-success?style=flat-square">
  <img src="https://img.shields.io/badge/Modes-Black%20%7C%20White%20%7C%20Grey%20%7C%20Host-9cf?style=flat-square">
  <img src="https://img.shields.io/badge/Auth-API%20key%20%7C%20Subscription-orange?style=flat-square">
</p>

<p align="center"><b>Autonomous, multi-model penetration-testing harness — Rust, CLI-only.</b><br>
<i>by Joas A Santos &amp; Red Team Leaders</i></p>

> ⭐ If this is useful, **star the repo** — it helps a lot.
>
> 📖 **New here? Read the [full Tutorial & User Guide →](TUTORIAL.md)** — every mode, flag, config and example explained.

> 🆕 **New in v3.5.4 — Robust attack chaining + fewer false positives:** a
> multi-round, decision-driven **post-exploitation** engine takes each confirmed
> foothold and expands new directions (cred reuse, privesc, lateral movement,
> exfil, new surface), carrying **loot** forward across rounds (`--chain-depth`).
> Validation is now **severity-aware** (High/Critical need ≥2 validators & ≥2/3
> agreement) with an **adversarial refute pass** that drops findings that can't
> withstand a skeptic.
> *(v3.5.3 added GitHub/GitLab/Jira **[integrations](TUTORIAL-INTEGRATION.md)**; v3.5.2 the DEPTH doctrine + report-hygiene pass — see [RELEASE.md](RELEASE.md).)*

---

**NeuroSploit** turns a URL, a source repository, a running app, or a host/IP into
an autonomous security engagement. A Rust harness (`tokio`) drives a **pool of
LLMs** — via **API key** or local **subscription** (Claude Code / Codex / Gemini /
Grok) — recons the target, **intelligently selects only the agents that match the
discovered surface**, runs them in parallel, **chains** findings into deeper
impact, and **validates every claim by cross-model voting + tool-receipt
grounding** before reporting. It ships **329 markdown agents** and a **Mission
Control TUI**.

### Engagement modes

| Mode | Command | What it does |
|------|---------|-------------|
| **Black-box** | `neurosploit run <url>` | recon → select → exploit → vote → report |
| **White-box** | `neurosploit whitebox <repo>` | source/SAST review (file:line evidence) |
| **Grey-box** | `neurosploit greybox <repo> --url <app>` | code review **+** live exploitation together |
| **Host/Infra** | `neurosploit host <ip> --creds creds.yaml` | Linux / Windows / Active Directory testing |
| **Mission Control** | `neurosploit tui <url>` | live TUI panels + composer during the run |
| **Interactive** | `neurosploit` | persistent REPL session (resumes per project) |

### Highlights

- 🧠 **POMDP belief + value-of-information** — the target is partially observable,
  so findings aren't booleans: a property-graph **belief** carries probabilities,
  and "scan more vs exploit now" falls out of belief entropy. The `may_assert`
  gate is a **mathematical anti-hallucination rule** (don't claim exploitability
  while the belief is diffuse).
- 🧾 **Grounding** — hard rule: **no claim without a tool receipt** (raw tool
  output, not paraphrase). Empirical for black-box, symbolic (`file:line`) for
  white-box; ungrounded claims are demoted.
- 🔗 **Attack chaining** — 12 multi-stage chain agents (SQLi→RCE→LPE, SSRF→AWS
  creds, upload→LFI→RCE→LPE, default-creds→domain, …); each stage proven before
  advancing.
- 🗺️ **Attack graph & kill chain** — findings mapped to OWASP / CWE / MITRE
  ATT&CK / stage; rendered as a Mermaid graph in the report.
- ✅ **Cross-model validation** — a different model adjudicates each finding;
  RL-weighted, recon-aware agent selection.
- 🛰️ **Mission Control TUI** — live header/feed/findings/targets panels + a
  composer you can type in *while the run streams* (`summary`, `pause`, …).
- 💾 **Per-project memory** — `<cwd>/.neurosploit/` keeps session, run history and
  command history; the REPL **resumes** on reopen. No database required.
- 🪙 **Token/cost telemetry**, per-agent attribution, graceful Ctrl-C → report or
  discard, Typst/HTML/JSON/MD reports.

> This is the **slim, Rust-only** distribution (`neurosploit-rs/` + `agents_md/`).
> The earlier Python engine and web GUIs live on the older `v3.4.0` branch.

---

## 📦 Install (one line)

**Linux / macOS** (x64 & arm64):
```bash
curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
```

**Windows** (PowerShell, x64 & arm64):
```powershell
irm https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/install.ps1 | iex
```

### Supported platforms

| OS | x64 | arm64 |
|----|-----|-------|
| **Linux** (Kali recommended) | ✅ | ✅ |
| **macOS** | ✅ | ✅ (Apple Silicon) |
| **Windows** | ✅ | ✅ |

Pure Rust + stdlib, so it builds natively everywhere a stable Rust toolchain runs.
The installer auto-detects OS/arch and installs Rust if missing. On native Windows
use `install.ps1`; under WSL2 / Git Bash the `setup.sh` one-liner also works.

The installer auto-installs Rust if needed, clones the repo to `~/.neurosploit`,
builds the release binary, and links `neurosploit` into `~/.local/bin`. Re-run it
any time to update. Tweak with env vars: `NEUROSPLOIT_REF` (branch/tag),
`NEUROSPLOIT_DIR`, `PREFIX`.

Prefer to build by hand?

```bash
git clone https://github.com/JoasASantos/NeuroSploit && cd NeuroSploit/neurosploit-rs
cargo build --release      # → target/release/neurosploit
```

## ⚡ Quick start (60 seconds)

```bash
# easiest path — just run it; the interactive session asks everything:
neurosploit

# or one-liner (subscription login, no API key needed):
neurosploit run http://testphp.vulnweb.com/ --model claude:claude-opus-4-8 -v

# white-box — review a source repository (SAST agents, file:line evidence):
git clone https://github.com/digininja/DVWA /tmp/DVWA
neurosploit whitebox /tmp/DVWA --model claude:claude-opus-4-8 -v

# grey-box — review the code AND exploit the running app together:
neurosploit greybox /tmp/DVWA --url http://localhost:8080/ --creds creds.yaml \
  --model claude:claude-opus-4-8 --mcp -v

# host / infra — Linux / Windows / Active Directory (SSH/Win creds in creds.yaml):
neurosploit host 10.0.0.10 --creds creds.yaml --model claude:claude-opus-4-8 -v

# 🛰  Mission Control TUI — live panels (header/feed/findings/targets) + a composer
#    you can type in WHILE the run streams (summary · pause · errors · notes):
neurosploit tui http://testphp.vulnweb.com/ --model claude:claude-opus-4-8 --mcp
```

> Full step-by-step for every mode (black/white/grey/host) is in **[TUTORIAL.md](TUTORIAL.md)**.

No login? Use an **API key** instead — see [Authentication](#authentication--run-via-api-key-or-subscription).

---

## 🔌 Integrations (GitHub · GitLab · Jira)

Wire NeuroSploit into your SDLC. Toggle from the REPL (`/integrations`) or the CLI
(`neurosploit integrations enable github|gitlab|jira`). **Tokens are never stored**
— only the *name* of the env var is saved; the value is read from your environment.

```bash
export GITHUB_TOKEN=ghp_...                 # PAT with `repo` scope (private repos)
neurosploit integrations enable github

# Review a Pull Request's code (clones the PR head, white-box) and comment back:
neurosploit pr digininja/DVWA 42 --model claude:claude-opus-4-8 --comment

# Watch a branch and re-review on every new commit:
neurosploit watch myorg/private-app --branch main --model claude:claude-opus-4-8

# Private GitLab repo (token-injected clone) — works in whitebox/greybox:
export GITLAB_TOKEN=glpat-... ; neurosploit integrations enable gitlab
neurosploit whitebox https://gitlab.com/myorg/private-svc --model claude:claude-opus-4-8

# Open a Jira card per finding (any engagement):
export JIRA_EMAIL=you@org.com JIRA_API_TOKEN=...      # set base/project once: /integrations setup jira
neurosploit whitebox https://github.com/myorg/app --jira --model claude:claude-opus-4-8
```

| Integration | What you get | Env vars |
|-------------|--------------|----------|
| **GitHub** | private clone · `pr` review + comment · `watch` branch | `GITHUB_TOKEN` |
| **GitLab** | private clone for whitebox/greybox | `GITLAB_TOKEN` |
| **Jira** | one card per finding (`--jira`) | `JIRA_EMAIL`, `JIRA_API_TOKEN` |

📖 Step-by-step setup for each tool: **[TUTORIAL-INTEGRATION.md](TUTORIAL-INTEGRATION.md)**.

---

## Build

```bash
cd neurosploit-rs
cargo build --release        # → target/release/neurosploit
```

Requires a Rust toolchain (`rustup`). **Recommended: run on Kali Linux** (or the
Kali Docker image) so the offensive tools the agents use are already present:

```bash
docker run -it --rm kalilinux/kali-rolling
apt update && apt install -y curl nmap ffuf nodejs npm
# rustscan (faster port scan): cargo install rustscan   (or grab a release from GitHub)
```

The agents degrade gracefully: if `rustscan` isn't installed they use `nmap`; if
neither, they probe with `curl`. If a Playwright MCP browser is available they use
it for JS-heavy pages, otherwise they fall back to `curl`.

---

## Usage

Run with **no arguments** for an interactive wizard:

```bash
./target/release/neurosploit
```

Or drive it directly:

```bash
# Black-box — subscription (no API key), Opus, browser via Playwright if present, verbose
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model claude:claude-opus-4-8 --mcp -v

# Black-box — API keys, multi-model voting panel (1st finds, others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3

# White-box — clone a vulnerable app and review its source
git clone https://github.com/digininja/DVWA /tmp/DVWA
./target/release/neurosploit whitebox /tmp/DVWA \
    --model claude:claude-opus-4-8 -v

# Offline pipeline self-test (no keys/login needed)
./target/release/neurosploit run http://testphp.vulnweb.com/ --offline

# Utilities
./target/release/neurosploit agents     # library counts
./target/release/neurosploit models      # providers & models
./target/release/neurosploit --help        # full help with examples
```

### Options (`run` / `whitebox`)

| Flag | Meaning |
|------|---------|
| `--model provider:model` | Repeatable. First = primary; the rest fail over **and** form the voting jury. Mix API (`anthropic:`, `openai:`, …) and subscription (`claude:`, `codex:`, `agy:`, `grok:`, `cursor:`) in one run. |
| `--mcp` | Enable Playwright MCP (auto-provisioned via `npx`; backends without MCP use built-in tools). |
| `--vote-n N` | How many models must agree a finding is real (default 3 / 2 for whitebox). |
| `--max-agents N` | Cap agents run (`0` = all matching the recon). |
| `--offline` | Exercise the full pipeline without calling any model. |
| `-v, --verbose` | Log each agent as it launches, recon, and votes. |

### Authentication — run via API key *or* subscription

You can run NeuroSploit two ways. They're independent: pick per run.

#### 1) Via API (provider API key)

Export the key(s) for the providers in your model panel. Any OpenAI-compatible provider works.

```bash
# pick one or more, depending on the models you select
export ANTHROPIC_API_KEY=sk-ant-...        # anthropic:claude-*
export OPENAI_API_KEY=sk-...               # openai:gpt-*
export GEMINI_API_KEY=AIza...              # gemini:gemini-*
export NVIDIA_NIM_API_KEY=nvapi-...        # nvidia_nim:*
export DEEPSEEK_API_KEY=...                # deepseek:*
export MISTRAL_API_KEY=...                 # mistral:*
export DASHSCOPE_API_KEY=...               # qwen:*  (Alibaba DashScope)
export GROQ_API_KEY=...                    # groq:*
export TOGETHER_API_KEY=...                # together:*
export OPENROUTER_API_KEY=...              # openrouter:*
# ollama needs no key (local)

# then run via API
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --vote-n 3 -v

# multi-provider voting panel via API (1st finds, the others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --model gemini:gemini-2.5-pro
```

Or put the keys in a `.env` and source it (`cp .env.example .env`; edit; `set -a; . ./.env; set +a`).

**Provider → env var → endpoint** (all OpenAI-compatible):

| `--model` prefix | Env var | Base URL |
|------------------|---------|----------|
| `anthropic:` | `ANTHROPIC_API_KEY` | api.anthropic.com |
| `openai:` | `OPENAI_API_KEY` | api.openai.com |
| `gemini:` | `GEMINI_API_KEY` | generativelanguage.googleapis.com |
| `xai:` | `XAI_API_KEY` | api.x.ai |
| `nvidia_nim:` | `NVIDIA_NIM_API_KEY` | integrate.api.nvidia.com |
| `deepseek:` | `DEEPSEEK_API_KEY` | api.deepseek.com |
| `mistral:` | `MISTRAL_API_KEY` | api.mistral.ai |
| `qwen:` | `DASHSCOPE_API_KEY` | dashscope-intl.aliyuncs.com |
| `groq:` | `GROQ_API_KEY` | api.groq.com |
| `together:` | `TOGETHER_API_KEY` | api.together.xyz |
| `openrouter:` | `OPENROUTER_API_KEY` | openrouter.ai |
| `ollama:` | _(none)_ | localhost:11434 |

Run `./target/release/neurosploit models` for the full provider/model list.

#### 2) Via subscription CLI (no API key)

Pick a **subscription provider key** in `--model` — install and log into the CLI first:

| `--model` prefix | CLI used | Login |
|------------------|----------|-------|
| `claude:` | `claude` (Claude Code) | `claude` then `/login` |
| `codex:` | `codex` | `codex` login |
| `agy:` | `agy` (Antigravity) | `agy` login |
| `grok:` | `grok` | `grok` login |
| `cursor:` / `agent:` | `agent` / `cursor-agent` | Cursor subscription |

```bash
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model claude:claude-opus-4-8 --mcp -v

# mixed API + subscription in one run
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model openrouter:minimax/minimax-m3 --model codex:gpt-5.3-codex -v
```

---

## How it works

```
target ─▶ recon (curl/nmap/…) ─▶ INTELLIGENT agent selection (recon-aware)
       ─▶ parallel exploitation ─▶ cross-model validation vote
       ─▶ severity/score ─▶ report (HTML + Typst PDF) ─▶ RL reward update
```

Every run writes a self-contained folder `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `status.json` | `running` → `complete` with a summary |
| `recon.json` / `recon.md` | mapped attack surface |
| `exploitation.md` | raw per-agent transcript |
| `findings.json` / `findings.md` | validated findings (reuse by other tools/AIs) |
| `report.html`, `report.typ`, `report.pdf` | final report (PDF via the Typst engine) |

A reinforcement-learning reward store (`data/rl_state_rs.json`) biases agent
selection on future runs.

## Agent library — `agents_md/` (303)

| Category | Count | Purpose |
|----------|-------|---------|
| `vulns/` | 196 | Exploit a specific vulnerability class |
| `recon/` | 12 | Information gathering / attack surface |
| `code/` | 78 | White-box source-code (SAST) review |
| `meta/` | 17 | Orchestrator, validator, scorers, reporter, RL |

Each agent is a self-contained markdown playbook (`## User Prompt` methodology +
`## System Prompt` strict anti-false-positive rules). Drop a new `.md` into the
matching folder and the harness picks it up.

---

## Safety

For **authorized** testing only. Agents are instructed to stay in scope, never run
destructive/DoS actions, and require proof-of-exploitation. You are responsible for
having permission for any target.

## Credits

**Joas A Santos** & **Red Team Leaders**.

## License

MIT.
