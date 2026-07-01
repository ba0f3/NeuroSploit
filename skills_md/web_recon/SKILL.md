---
name: web_recon
description: Map the attack surface of a web application.
tags: [web, recon, crawler]
tools: [httpx, whatweb, katana, gau, curl, gobuster, dirsearch, ffuf]
---
# Web Reconnaissance Skill

## Objective
Enumerate technologies, endpoints, directories, and parameters.

## Procedure
1. **Liveness**: Probe with `httpx` and `curl`.
2. **Technology fingerprint**: Run `whatweb` and inspect headers/cookies.
3. **Crawl**: Use `katana` and `gau` to discover URLs and JS files.
4. **Directory brute**: Run `gobuster dir` or `ffuf` with a wordlist.
5. **Parameter discovery**: Note forms, query parameters, headers, and cookies.

## Output
Return JSON: `{url, tech_stack, endpoints: [{path, method, params}], directories, js_files}`.
