# Tailored vulnerability tables

## JavaScript-Based Web Apps (React/Angular/Vue)

| Vulnerability	           | Likelihood	 | Impact	   | Testing Focus	                                   | Tools                              |
|--------------------------|-------------|-----------|--------------------------------------------------|------------------------------------|
| DOM XSS	                 | 40-60%	     | High	     | `innerHTML`, `eval()`, `document.write`	         | Burp DOM Invader, Manual JS Review |
| JWT Misconfig	           | 30-50%	     | Critical	 | `alg: none`, weak secrets, token storage	        | jwt_tool, Burp JWT Editor          |
| CORS Misconfig	          | 25-40%	     | High	     | Overly permissive `Access-Control-Allow-Origin`	 | cors-scanner, Burp                 |
| Client-Side Logic Flaws	 | 20-35%	     | Medium	   | Price tampering, fake discounts	                 | Chrome DevTools, Manual Testing    |
| Prototype Pollution	     | 10-20%	     | High	     | `__proto__`, `constructor` abuse	                | PPFuzz, Manual JS Analysis         |

Priority Order: DOM XSS → JWT → CORS → Client-Side Logic → Prototype Pollution.

## Python Web Apps (Django/Flask)

| Vulnerability	      | Likelihood	 | Impact	   | Testing Focus	                                   | Tools                         |
|---------------------|-------------|-----------|--------------------------------------------------|-------------------------------|
| SQLi	               | 15-30%	     | Critical	 | ORM bypass (`raw()` queries), string formatting	 | SQLmap, Manual Testing        |
| SSTI (Jinja2/Mako)	 | 10-25%	     | High	     | `{{7*7}}`, RCE via template injection	           | tplmap, Manual Probing        |
| Pickle RCE	         | 5-15%	      | Critical	 | `pickle.loads(user_input)`	                      | Fickling, Manual Exploitation |
| CSRF Bypass	        | 10-20%	     | Medium	   | Missing `@csrf_protect` (Django)	                | Burp CSRF PoC Generator       |
| Auth Bypass	        | 20-30%	     | High	     | Weak session management, password reset flaws	   | Manual Testing, Hydra         |

Priority Order: SQLi → SSTI → Auth Bypass → CSRF → Pickle RCE.

## APIs (REST/GraphQL)

| Vulnerability	               | Likelihood	 | Impact	   | Testing Focus	                        | Tools                           |
|------------------------------|-------------|-----------|---------------------------------------|---------------------------------|
| IDOR	                        | 30-50%	     | Critical	 | `/api/user/123` → `/api/user/124`	    | Burp (Autorize), Manual Testing |
| JWT Issues	                  | 25-45%	     | High	     | Algorithm confusion, expired tokens	  | jwt_tool, Burp Suite            |
| GraphQL Introspection Abuse	 | 20-35%	     | Medium	   | Exposed schemas, batch query attacks	 | GraphQL Cop, InQL Scanner       |
| Rate-Limiting Bypass	        | 15-30%	     | Medium	   | Brute-force/login flooding	           | Burp Intruder, custom scripts   |
| Mass Assignment	             | 10-25%	     | High	     | `{"role":"admin"}` in JSON payloads	  | Manual Testing, Burp Repeater   |

Priority Order: IDOR → JWT → GraphQL → Mass Assignment → Rate-Limiting.

## Cloud Pipelines (CI/CD, Serverless)

| Vulnerability	        | Likelihood	 | Impact	   | Testing Focus	                          | Tools                             |
|-----------------------|-------------|-----------|-----------------------------------------|-----------------------------------|
| Secrets in Logs/Env	  | 30-50%	     | Critical	 | AWS keys, DB creds in build logs	       | TruffleHog, GitLeaks              |
| Over-Permissive IAM	  | 25-45%	     | High	     | AWS `*` policies, privilege escalation	 | Pacu, AWS CLI                     |
| CI/CD Code Injection	 | 15-30%	     | Critical	 | Malicious PRs triggering pipelines	     | Manual Review, Semgrep            |
| Serverless SSRF	      | 10-25%	     | High	     | Lambda → AWS metadata API access	       | Burp Collaborator, manual testing |
| Unsecured Storage	    | 20-40%	     | Medium	   | Public S3 buckets, Azure blobs	         | AWS S3 Scanner, manual checks     |

Priority Order: Secrets → IAM → CI/CD Injection → SSRF → Storage.