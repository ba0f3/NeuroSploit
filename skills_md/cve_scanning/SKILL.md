---
name: cve_scanning
description: Identify known vulnerabilities in exposed services and components.
tags: [cve, vulnscan, web, network]
tools: [nuclei, nmap, whatweb]
---
# CVE Scanning Skill

## Objective
Map detected services and technologies to known CVEs and verify them safely.

## Procedure
1. **Input**: Use recon data (service versions, tech stack).
2. **Template scan**: Run `nuclei` against the target with relevant templates.
3. **Version correlation**: Query known CVE databases for identified versions.
4. **Safe verification**: Only run non-destructive PoCs.

## Output
JSON findings: `{title, cve, severity, endpoint, evidence, remediation}`.
