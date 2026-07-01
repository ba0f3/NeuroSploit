# Tool Recipe Authoring

Tool recipes live in `toolsdata/**/*.yaml`. They are used both to build command
argv and to validate model tool calls before execution.

## Semantic Parameters

Use `target_format` on target-like parameters:

| Format | Use for | Example |
|---|---|---|
| `host_or_ip` | host scanners such as `nmap` | `example.com` |
| `url` | web tools such as `katana` and `curl` | `https://example.com/path` |
| `url_with_fuzz` | fuzzers such as `ffuf` | `https://example.com/FUZZ` |
| `domain` | DNS/OSINT tools | `example.com` |
| `cidr` | network range tools | `192.0.2.0/24` |

Use `min` and `max` for integers, `enum` for closed sets, and `pattern` for
compact string validation such as port lists.

## Additional Args

Prefer typed parameters over `additional_args`. If a recipe keeps
`additional_args`, declare `allowed_flags` and keep `allow_shell: false` unless
there is a reviewed reason to permit shell syntax.

## Examples

```yaml
- name: target
  type: string
  description: Hostname or IP to scan.
  required: true
  position: 0
  format: positional
  target_format: host_or_ip

- name: depth
  type: int
  description: Crawl depth.
  default: 3
  flag: -d
  format: combined
  min: 1
  max: 10
```
