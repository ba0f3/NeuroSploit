---
name: xss_testing
description: Detect reflected, stored, and DOM-based XSS.
tags: [xss, web, exploit]
tools: [dalfox, curl]
---
# XSS Testing Skill

## Objective
Find cross-site scripting vulnerabilities and prove JavaScript execution.

## Procedure
1. **Identify sinks**: URL parameters, form fields, headers, DOM sinks.
2. **Reflected XSS**: Inject `<script>alert(document.domain)</script>` and verify reflection.
3. **Stored XSS**: Submit payloads in persistent inputs and verify execution by other users.
4. **DOM XSS**: Trace source→sink via JavaScript analysis.
5. **Automation**: Run `dalfox` for systematic detection.

## Output
Findings with CWE-79 and screenshot/response evidence.
