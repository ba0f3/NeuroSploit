---
name: network_recon
description: Discover live hosts, open ports, services, and versions on a target network.
tags: [network, recon, portscan]
tools: [nmap, rustscan, naabu, whois, dig]
---
# Network Reconnaissance Skill

## Objective
Map the network attack surface before attempting exploitation.

## Procedure
1. **Host discovery**: Confirm the target is reachable (`ping`, `nmap -sn`).
2. **Port scanning**: Run `nmap -sV -sC -Pn <target>` or `rustscan -a <target>`.
3. **Service fingerprinting**: Record banners, versions, and unusual ports.
4. **DNS recon**: Use `dig` and `whois` to map domains and name servers.
5. **CVE mapping**: Correlate identified versions to known CVEs for later agents.

## Output
Return a JSON summary: `{host, open_ports: [{port, service, version, cpe}], os_guess, dns_records, notes}`.
