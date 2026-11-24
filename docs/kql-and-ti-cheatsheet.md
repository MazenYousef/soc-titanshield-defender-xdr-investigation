# KQL and Threat-Intel Quick Reference

[← Back to the main README](../README.md)

## Threat-intelligence workflow (Microsoft Defender XDR)

| Step | Where | What you get |
|---|---|---|
| 1. Search an indicator (hash, domain, IP) | Defender XDR → Threat intelligence → **Intel Explorer** | Reputation score, first/last seen, related indicators |
| 2. Open attribution | **Intel Profiles → actor profile** | Country, motivation, targeted sectors, related actors, TTPs |
| 3. Read linked articles | **Articles** on the indicator page | Campaign narrative, timeline, delivery methods, **new IOCs** |
| 4. Hunt the new IOCs internally | KQL against your own logs | Scope: who else was hit, what happened next |
| 5. Expand infrastructure | **Passive DNS** (domain ↔ IP history) | More IPs and domains to block and hunt |

## KQL patterns used

| Pattern | Example | Purpose |
|---|---|---|
| Case-insensitive list match | `\| where filename in~ ("nvunityplugin.dll", "unityplayer.dll")` | Hunting TI-provided file names |
| Any of several IOCs | `\| where process_commandline has_any ("mingeloem.com", "matrixane.com")` | Hunting C2 domains in command lines |
| All parts of a behaviour | `\| where process_commandline has_all ("echo", ">>", "logs.txt")` | Pivoting on a command *pattern* |
| Enrich with people and roles | `\| join kind=inner Employees on $left.recipient == $right.email_addr` | Who was targeted, by role |
| Pull the domain out of a URL | `\| extend domain = tostring(parse_url(link).Host)` | Domains in phishing links |
| Sub-query as a filter | `let ips = PassiveDns \| where domain in (d) \| distinct ip;` then `\| where src_ip in (ips)` | Infrastructure pivots |
| Timeline around an event | `\| where timestamp between (datetime(...) .. datetime(...)) \| order by timestamp asc` | Finding what ran right before |

## Pivot chain used in Case 2

```
EDR alert (whoami) ─► command pattern (echo >> Logs.txt) ─► 663 events / 15 hosts / one team
  └► patient zero timeline ─► macro.xlsm ─► .xlsx created by Edge.exe ─► download URL
       └► email with that link ─► sender ─► all 13 emails ─► 3 domains ─► Defender TI attribution
            └► Passive DNS ─► 2 IPs ─► InboundNetworkEvents ─► recon from 5 July (LinkedIn)
                 └► exfiltration mailbox ─► victim and impact
```
