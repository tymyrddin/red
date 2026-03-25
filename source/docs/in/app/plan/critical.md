# Prioritised vulnerability tables

## Critical vulnerabilities (Test first)

| Vulnerability | Likelihood | Impact | Testing Method | Tools |
|---|---|---|---|---|
| Broken Access Control (IDOR/BFLA) | 30-40% | Data breaches, privilege escalation | Manual role-switching, ID substitution, Autorize sweep | Burp (Autorize), OWASP ZAP |
| Business Logic / Workflow Abuse | 25-50% | Financial loss, privilege gain, account takeover | Workflow step-skipping, parameter substitution across steps, race conditions | Turbo Intruder, custom scripts, Burp macros |
| SQL Injection | 10-20% | Full DB compromise | Boolean/time-based detection, UNION extraction | SQLmap, Burp Scanner |
| XSS (DOM/Stored/Reflected) | 40-60% | Session hijacking, account takeover | Context-specific payloads, DOM Invader, OOB cookie theft | Burp DOM Invader, manual |
| SSRF | 15-25% | Internal network access, cloud credential theft | OOB probe first, then metadata service | Burp Collaborator, Interactsh |
| Authentication Bypass | 20-35% | Account takeover | JWT algorithm confusion, 2FA skip, password reset poisoning | jwt_tool, Burp |

Business logic is the primary battlefield in modern applications. Scanners cannot detect it.
Test it before moving to injection classes.

## High-risk vulnerabilities (Test next)

| Vulnerability | Likelihood | Impact | Testing Method | Tools |
|---|---|---|---|---|
| HTTP Request Smuggling | 10-20% | Access control bypass, session hijacking | CL.TE/TE.CL timing probes, HTTP/2 downgrade | Burp (HTTP Request Smuggler), Turbo Intruder |
| Insecure Deserialisation | 5-15% | RCE | Java/Python gadget chains | ysoserial, Fickling |
| CSRF | 10-20% | Unauthorised state-changing actions | Craft cross-origin form, test SameSite and token absence | Burp CSRF PoC generator |
| CORS Misconfiguration | 20-30% | Data theft, credential exposure | `Origin: attacker.com` injection, null origin | cors-scanner, Burp |
| File Upload Vulnerabilities | 15-25% | RCE, persistent XSS | Upload `.php`, polyglot files, MIME type bypass | Manual, Metasploit |

## Medium/Low-risk vulnerabilities (Test last)

| Vulnerability | Likelihood | Impact | Testing Method | Tools |
|---|---|---|---|---|
| Clickjacking | 15-25% | UI deception, CSRF amplification | Check `X-Frame-Options`, test iframe embedding | Burp, manual |
| Prototype Pollution | 5-15% | RCE, XSS via gadgets | `__proto__` and `constructor` injection, DOM Invader scanner | Burp DOM Invader, PPFuzz |
| Web Cache Poisoning | 10-20% | Defacement, stored XSS delivery | `X-Forwarded-Host` abuse, unkeyed header injection | Param Miner, Burp |
| XXE | 5-10% | Data leaks, SSRF | OOB DOCTYPE payload, local file read | manual, XXEinjector |

## Notes

- Business logic flaws require manual testing but appear in almost every application. They
  are listed as critical because they have the highest hit rate and highest impact per hour
  of testing.
- HTTP request smuggling is infrastructure-dependent: high impact when present, but only
  present when a reverse proxy sits in front of the application.
- [Adapt based on tech stack](adapted.md) — prioritise SSTI for Jinja2 apps, JWT issues
  for API-heavy applications, and client-side desync for SPA frontends behind proxies.
