---
name: file_upload_testing
description: Test file upload functionality for malicious file execution.
tags: [web, upload, exploit]
tools: [curl]
---
# File Upload Testing Skill

## Objective
Bypass upload restrictions to achieve code execution or stored XSS.

## Procedure
1. **Extension bypass**: Try double extensions, null bytes, case variations.
2. **Content-type bypass**: Change MIME types while keeping malicious content.
3. **Magic bytes**: Prepend valid image headers to PHP/shell payloads.
4. **Path traversal**: Use `../` in filenames to write to arbitrary locations.
5. **Chain**: Combine upload with LFI/RFI to execute code.

## Output
Findings with CWE-434 and evidence of uploaded file execution.
