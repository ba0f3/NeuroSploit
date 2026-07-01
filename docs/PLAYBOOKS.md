# NeuroSploit Playbooks

Playbooks are YAML workflows in `playbooks/` that run phased pentest sequences: recon tools → specialist agents → chaining. Use `--playbook` to run one instead of the default pipeline.

## Layout

```
playbooks/
├── owasp-top10.yaml
└── api-security.yaml
```

## YAML format

```yaml
name: OWASP Top 10
description: Focused black-box assessment against OWASP Top 10.
tags: [web, owasp]
variables:
  - name: target
    type: string
    required: true
phases:
  - name: recon
    tools: [httpx, whatweb, katana]
    agents: [tech_fingerprint]
    skills: [web_recon]
    post_analysis: |
      Extract tech stack and endpoints for downstream agents.
  - name: vulnerabilities
    condition: recon          # runs when recon phase completed
    tools: [nuclei, dalfox]
    agents: [sqli_error, xss_reflected]
    skills: [sqli_testing]
  - name: chain
    condition: "findings_count > 0"
    agents: [chain_upload_lfi_rce_lpe]
```

### Phase fields

| Field | Purpose |
|-------|---------|
| `name` | Phase identifier; sets `state[name]=true` when done |
| `condition` | Skip phase if false (`recon`, `findings_count > 0`, `key == value`) |
| `tools` | Allowlisted tools run sequentially |
| `agents` | Specialist agents invoked via the toolloop |
| `skills` | Skill blocks added to phase state |
| `post_analysis` | Guidance stored in state for agents |

## CLI usage

```bash
# Run the OWASP Top 10 playbook with auto tool execution
./neurosploit run https://target.example \
  --playbook "OWASP Top 10" \
  --auto-tools \
  --subscription

# Prompt before each tool command
./neurosploit run https://target.example --playbook api-security --interactive
```

## Adding a playbook

1. Add `playbooks/<slug>.yaml` at the repo root.
2. Use agent names exactly as in `agents_md/` (without `.md`).
3. Run `go test ./internal/playbooks/...` from `neurosploit-go/`.
