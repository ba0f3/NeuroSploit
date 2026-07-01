---
name: auth_testing
description: Test authentication mechanisms for bypass, brute force, and session flaws.
tags: [auth, web, exploit]
tools: [curl, ffuf]
---
# Authentication Testing Skill

## Objective
Find weak authentication, session fixation, JWT flaws, and 2FA bypass.

## Procedure
1. **Credential stuffing**: Test weak/default credentials.
2. **JWT analysis**: Check algorithm confusion, weak secrets, and expired tokens.
3. **Session management**: Test fixation, predictable tokens, and logout.
4. **Rate limiting**: Verify brute-force protections.

## Output
JSON findings with CWE-287, CWE-384, CWE-521, etc.
