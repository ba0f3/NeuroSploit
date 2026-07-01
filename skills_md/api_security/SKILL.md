---
name: api_security
description: Assess REST and GraphQL APIs for common vulnerabilities.
tags: [api, web, recon, exploit]
tools: [httpx, katana, curl, nuclei]
---
# API Security Skill

## Objective
Find broken authentication, BOLA/IDOR, mass assignment, and excessive data exposure.

## Procedure
1. **Discovery**: Find `/api`, `/v1`, `/graphql`, swagger docs, and JS references.
2. **Authentication**: Test token/JWT handling with `curl`.
3. **Authorization**: Test IDOR by swapping object IDs.
4. **Input validation**: Fuzz parameters for injection, SSRF, and mass assignment.
5. **Rate limiting**: Check throttling with repeated requests.

## Output
Return JSON findings with CWE-639 (BOLA), CWE-285 (BFLA), CWE-200, etc.
