package pipeline

import (
	"fmt"
	"strings"

	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/agents"
	"github.com/JoasASantos/NeuroSploit/neurosploit-go/internal/types"
)

const reconSys = "You are a web recon specialist on an AUTHORIZED engagement. You have shell tools (curl etc.) — actively fetch the target, enumerate pages/params, and map the real attack surface. Do not ask for permission; proceed. Reply with a compact JSON object (tech, endpoints, params, auth, apis). No prose."

const voteSys = "You are an adversarial security validator. Decide if the candidate finding is a REAL, reproducible, exploitable vulnerability whose EVIDENCE actually proves impact. Reject common false positives: input merely reflected but not executed; version/banner guesses with no working PoC; self-XSS; theoretical issues; an error message or stack trace mistaken for injection; missing, generic, or non-reproducible evidence; severity inflated beyond what the evidence demonstrates. Confirm only if the provided evidence (request/response) concretely proves the vulnerability. Reply with JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}. Default to rejected when uncertain."

const refuteSys = "You are a skeptical senior reviewer trying to DISPROVE a reported vulnerability. Assume it is a FALSE POSITIVE unless the evidence forces otherwise. Scrutinize: does the evidence PROVE execution/impact, or only that input was reflected/accepted? Is there a real working PoC, or just a version/banner/theory? Could it be self-XSS, an error message, or an unreachable path? Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"} where confirmed means the vulnerability is REAL and proven by the evidence. When in doubt, reject."

const codeVoteSys = "You are an adversarial source-code reviewer. Decide if the reported issue is a REAL vulnerability in the provided code (reachable, exploitable, not a false positive). Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}."

const reactDoctrine = "METHOD (ReAct): work in explicit Thought → Action → Observation cycles. Each Action MUST invoke a tool via native tool_calls or <tool_call> JSON — plain-text curl/shell in prose is NOT executed. Read each real Observation before the next step. Base every claim on actual tool output — never assume. Stop only after you have proven an issue or exhausted reasonable checks including sqlmap/dalfox when curl is inconclusive.\n\n"

const depthDoctrine = "DEPTH (exploit, don't just expose):\n" +
	"- Exposed → exploited: any info-disclosure, exposed service/catalog/WSDL, leaked credential/token, or non-prod (dev/staging) host you find MUST be USED before you report it — call the exposed endpoint, decode the leaked artifact, log in with the leaked credential, hit the dev host. If you only observed it but never used it, report it as a LEAD (low confidence), not a confirmed finding.\n" +
	"- Chain across steps: reuse any session/JWT/cookie/credential you obtain in one step against every other module; if one bug yields access, pivot it into IDOR/privesc/data-exfil and report the CHAIN, not isolated parts.\n" +
	"- Decode & fingerprint → CVE: decode opaque tokens/paths (base64/JSON/marshal) and fingerprint the stack (server, framework, library/gem/plugin versions); map exact versions to known CVEs and attempt a safe, non-destructive PoC.\n" +
	"- Audit tokens: for any JWT, check alg-confusion (RS→HS), alg:none, kid/jku injection, whether the signature is actually verified, and weak/guessable HS256 secrets.\n" +
	"- Calibrate honestly: claim High/Critical ONLY when impact is DEMONSTRATED; unproven DoS/abuse is Low/Info or a lead, never inflated.\n\n"

const chainSys = "You are a post-exploitation & attack-chaining specialist. You are given ONE confirmed foothold plus any loot already gathered. DECIDE the most promising directions to expand from THIS foothold and pursue them with real tools: post-exploitation (loot credentials/tokens/keys/config/source), credential reuse, privilege escalation (horizontal AND vertical), lateral movement to adjacent services/hosts, data exfiltration, and reaching NEW attack surface the foothold exposes (e.g. SSRF→cloud metadata creds→IAM, SQLi→DB dump→credential reuse→admin, arbitrary file read→secrets→RCE, IDOR→account takeover, auth bypass→internal APIs). PROVE each escalated step with a real tool receipt. Report ONLY NEW findings beyond the input, plus any new loot you discovered (creds, tokens, hosts, internal endpoints) so later stages can reuse it. Authorized engagement; never destructive/DoS."

const evidenceDoctrine = "EVIDENCE: every finding MUST include a concrete `evidence` field — raw HTTP request/response excerpt, command stdout, or tool receipt. Claims without observable proof are leads, not findings.\n\n"

const severityDoctrine = "SEVERITY: Critical/High only when impact is DEMONSTRATED (data exfil, RCE, auth bypass proven). Theoretical or unproven issues → Medium/Low/Info. Never inflate.\n\n"

const outputSchemaDoctrine = "OUTPUT: reply ONLY with a JSON array of findings (may be []). Each item: {id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}. No prose outside the array.\n\n"

const selectSys = "You are a penetration-test orchestrator. Given recon of a target and a catalog of specialist agents, choose ONLY the agents whose preconditions clearly match the target's attack surface. Be selective. Reply with a JSON array of agent names (strings) drawn exactly from the catalog. No prose."

const hostReconSys = "You are an infrastructure recon specialist on an AUTHORIZED engagement against a HOST/IP. Actively scan with rustscan/nmap (and netexec/smbclient where relevant) to map open ports, services, versions and auth surfaces. Use any provided SSH/Windows credentials to enumerate from inside. Do not ask permission; proceed. Reply with a compact JSON object (host, os, ports, services, auth, ad). No prose."

const hostTooling = "TOOLING (best on Kali): nmap/rustscan (ports), netexec/crackmapexec + smbclient (SMB/AD), ssh/sshpass + linpeas (Linux), evil-winrm + winPEAS + impacket (Windows), bloodhound-python/SharpHound (AD), hashcat (offline cracking). Use only supplied credentials; never brute force or run destructive/DoS actions.\n\n"

func agentOutputSchema(ag agents.Agent) string {
	if ag.OutputSchema == "" {
		return outputSchemaDoctrine
	}
	return "OUTPUT SCHEMA (follow exactly):\n" + ag.OutputSchema + "\n\n"
}

func operatorDirectives(cfg types.RunConfig) string {
	var s strings.Builder
	if cfg.Instructions != nil {
		if focus := strings.TrimSpace(*cfg.Instructions); focus != "" {
			fmt.Fprintf(&s, "OPERATOR FOCUS — prioritise this: %s\n", focus)
		}
	}
	if cfg.Auth != nil {
		if auth := strings.TrimSpace(*cfg.Auth); auth != "" {
			fmt.Fprintf(&s, "AUTHENTICATION — test as an authenticated user; send this with each request: %s\n", auth)
		}
	}
	if s.Len() > 0 {
		s.WriteByte('\n')
	}
	return s.String()
}

func toolDoctrine(mcpOn bool) string {
	browser := "No browser MCP is available — use `curl` (and `wget`) for all HTTP interaction; render/inspect responses directly."
	if mcpOn {
		browser = "A Playwright MCP browser IS available — use it for JS-heavy pages, DOM/JS execution, and to PROVE client-side issues (e.g. XSS firing); capture screenshots as evidence."
	}
	return fmt.Sprintf(
		"TOOLING (authorized; best on Kali Linux or the kalilinux/kali-rolling Docker image):\n"+
			"- HTTP: `curl` (headers, methods, params, cookies), `wget`.\n"+
			"- Ports/services: `rustscan` if present, else `nmap`; if neither is installed you may "+
			"install via apt (`apt install -y nmap`), brew, or cargo (`cargo install rustscan`) — "+
			"otherwise probe common ports with `curl`/`nc`.\n"+
			"- Content/params: `ffuf`, `gobuster`, `gau`, `katana` when available.\n"+
			"- Tool argument shapes: host scanners (`nmap`, `rustscan`, `naabu`) take host/IP only, not `http://` URLs; web tools (`katana`, `httpx`, `nuclei`, `curl`) take full URLs; fuzzers require an explicit `FUZZ` marker where applicable.\n"+
			"- %s\n"+
			"Use only what is installed; degrade gracefully. Never run destructive or DoS actions.\n\n",
		browser,
	)
}
