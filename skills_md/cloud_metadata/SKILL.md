---
name: cloud_metadata
description: Test for cloud metadata service exposure and SSRF to metadata endpoints.
tags: [cloud, ssrf, web, exploit]
tools: [curl, nuclei]
---
# Cloud Metadata Exposure Skill

## Objective
Detect SSRF or misconfigured access to cloud metadata endpoints (IMDS).

## Procedure
1. **Identify SSRF vectors**: URLs, headers, webhooks.
2. **Probe metadata endpoints**: `http://169.254.169.254/latest/meta-data/` (AWS), `http://169.254.169.254/metadata/instance?api-version=...` (Azure).
3. **Escalate**: If credentials are exposed, attempt lateral movement.

## Output
Findings with CWE-918 (SSRF) and evidence of successful metadata retrieval.
