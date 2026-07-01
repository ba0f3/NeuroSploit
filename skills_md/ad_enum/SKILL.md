---
name: ad_enum
description: Enumerate Active Directory users, groups, and misconfigurations.
tags: [ad, windows, host, post]
tools: [netexec, smbclient, dig]
---
# Active Directory Enumeration Skill

## Objective
Discover AD users, shares, and privilege escalation paths.

## Procedure
1. **SMB enumeration**: `netexec smb <target>` and `smbclient -L`.
2. **User enumeration**: Check AS-REP roasting and password policies.
3. **Share hunting**: List accessible shares and search for sensitive files.
4. **ACL review**: Identify dangerous privileges (DCSync, GenericAll, etc.).

## Output
JSON: `{users, groups, shares, vulnerabilities, lateral_paths}`.
