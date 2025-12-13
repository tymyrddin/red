# Prioritised vulnerability tables

## Critical vulnerabilities (Test first)

| Vulnerability	                     | Likelihood (2025)	 | Impact	                  | Testing Method	                          | Tools                        |
|------------------------------------|--------------------|--------------------------|------------------------------------------|------------------------------|
| Broken Access Control (IDOR/FLAC)	 | 30-40%	            | Data breaches, RCE	      | Manual role-switching, ID tampering	     | Burp (Autorize), OWASP ZAP   |
| SQL Injection (SQLi)	              | 10-20%	            | Full DB compromise	      | `' OR 1=1--`, `UNION` attacks	           | SQLmap, Burp Scanner         |
| XSS (DOM/Stored/Reflected)	        | 40-60%	            | Session hijacking	       | `<script>alert(1)</script>`, DOM probes	 | Burp DOM Invader, XSS Hunter |
| SSRF	                              | 15-25%	            | Internal network access	 | `http://169.254.169.254` probes	         | Burp Collaborator, ffuf      |
| Authentication Bypass	             | 20-35%	            | Account takeover	        | Brute-force, MFA bypass, JWT flaws	      | Hydra, JWT_tool              |

## High-risk vulnerabilities (Test next)

| Vulnerability	            | Likelihood	 | Impact	               | Testing Method	                      | Tools                          |
|---------------------------|-------------|-----------------------|--------------------------------------|--------------------------------|
| Business Logic Flaws	     | 25-50%	     | Financial loss	       | Race conditions, pricing tampering	  | Manual testing, custom scripts |
| Insecure Deserial	 | 5-15%	      | RCE	                  | Java/Python gadget chains	           | ysoserial, Fickling            |
| CSRF	                     | 10-20%	     | Unauthorized actions	 | Craft malicious forms, token checks	 | Burp CSRF PoC generator        |
| CORS Misconfig	           | 20-30%	     | Data theft	           | `Origin: evil.com` injection	        | Burp, cors-scanner             |
| File Upload Vulns	        | 15-25%	     | RCE, malware	         | Upload `.php`, polyglot files	       | Manual testing, Metasploit     |

## Medium/Low-risk vulnerabilities (Test last)

| Vulnerability	          | Likelihood	 | Impact	          | Testing Method	                              | Tools                     |
|-------------------------|-------------|------------------|----------------------------------------------|---------------------------|
| Clickjacking	           | 15-25%	     | UI deception	    | Check `X-Frame-Options`, CSP	                | Burp, clickjack-test.py   |
| HTTP Request Smuggling	 | 10-20%	     | Cache poisoning	 | `CL.TE/TE.CL` attacks	                       | Burp (Smuggler extension) |
| Prototype Pollution	    | 5-15%	      | RCE, XSS	        | `__proto__` injections	                      | Burp DOM Invader, PPFuzz  |
| Cache Poisoning	        | 10-20%	     | Defacement	      | `X-Forwarded-Host` abuse	                    | Param Miner, Burp         |
| XXE	                    | 5-10%	      | Data leaks	      | `<!ENTITY xxe SYSTEM "file:///etc/passwd">`	 | OWASP ZAP, XXEinjector    |

## Accounting

* Critical vulns are easy to exploit and cause maximum damage.
* Business logic flaws require manual testing but are high-impact.
* Low-risk vulns (like Clickjacking) are quick to verify.
* [Adapt based on the app’s tech stack](adapted.md) (e.g., prioritise JWT flaws for APIs, SSTI for Jinja2 apps).
