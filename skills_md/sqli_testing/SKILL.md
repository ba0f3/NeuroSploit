---
name: sqli_testing
description: Detect and exploit SQL injection vulnerabilities.
tags: [sql, web, exploit]
tools: [sqlmap, curl]
---
# SQL Injection Testing Skill

## Objective
Find SQL injection and extract data or achieve code execution.

## Procedure
1. **Identify injection points**: URL parameters, forms, headers, cookies.
2. **Error-based detection**: Inject quotes and SQL keywords.
3. **Boolean/blind**: Use conditional responses and time delays.
4. **Union**: Extract data via UNION SELECT.
5. **Exploitation**: Use `sqlmap` to dump databases or execute commands.

## Output
Findings with CWE-89 and evidence: error messages, extracted data, or PoC requests.
