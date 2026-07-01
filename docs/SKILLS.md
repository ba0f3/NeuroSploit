# NeuroSploit Skills

Skills are reusable methodology blocks stored in `skills_md/`. Each skill is a `SKILL.md` file with YAML front matter and a Markdown body. The harness injects skill content into agent prompts when an agent lists the skill in its `## Skills` section, or when you pass `--auto-skills` with `--skills`.

## Layout

```
skills_md/
├── network_recon/SKILL.md
├── web_recon/SKILL.md
├── api_security/SKILL.md
├── cve_scanning/SKILL.md
├── ad_enum/SKILL.md
├── cloud_metadata/SKILL.md
├── auth_testing/SKILL.md
├── file_upload_testing/SKILL.md
├── sqli_testing/SKILL.md
└── xss_testing/SKILL.md
```

## SKILL.md format

```markdown
---
name: sqli_testing
description: Structured SQL injection testing methodology
tools: [curl, sqlmap, dalfox]
---

# SQL Injection Testing

Step-by-step guidance injected into agent prompts…
```

## CLI usage

```bash
# Inject specific skills into all agents that run
./neurosploit run https://target.example --auto-skills --skills sqli_testing,xss_testing

# Agents with ## Skills metadata get those skills automatically
```

## Adding a skill

1. Create `skills_md/<name>/SKILL.md` with front matter + body.
2. Reference the skill from agent markdown: `## Skills` section.
3. Run `go test ./internal/skills/...` from `neurosploit-go/`.
