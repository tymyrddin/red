# Tailored vulnerability tables

## JavaScript-Based Web Apps (React/Angular/Vue/SPA)

| Vulnerability | Likelihood | Impact | Testing Focus | Tools |
|---|---|---|---|---|
| DOM XSS | 40-60% | High | `innerHTML`, `eval()`, `document.write`, hash/search sources | Burp DOM Invader, manual JS review |
| JWT Misconfiguration | 30-50% | Critical | `alg: none`, weak secrets, token storage in localStorage | jwt_tool, Burp JWT Editor |
| CORS Misconfiguration | 25-40% | High | Overly permissive `Access-Control-Allow-Origin`, null origin | cors-scanner, Burp |
| Client-Side Desync | 10-20% | High | Server responses that leave connections in desync state, browser-exploitable | Burp (HTTP Request Smuggler), manual |
| Client-Side Logic Flaws | 20-35% | Medium | Price tampering, role flags in localStorage, workflow enforced only in frontend | Chrome DevTools, manual |
| WebSocket Abuse | 10-25% | High | Auth bypass on WS handshake, IDOR via message IDs, injection in message handlers | Burp WS history, manual |
| Prototype Pollution | 10-20% | High | `__proto__`, `constructor` abuse via URL params or JSON | PPFuzz, Burp DOM Invader |

Priority: DOM XSS → JWT → Client-Side Desync → WebSocket → CORS → Logic → Prototype Pollution

## Python Web Apps (Django/Flask/FastAPI)

| Vulnerability | Likelihood | Impact | Testing Focus | Tools |
|---|---|---|---|---|
| SSTI (Jinja2/Mako) | 10-25% | Critical | `{{7*7}}`, RCE via template injection | tplmap, manual probing |
| SQLi | 15-30% | Critical | ORM bypass (`raw()` queries), string formatting with `%` | SQLmap, manual |
| Pickle RCE | 5-15% | Critical | `pickle.loads(user_input)` in deserialisaton endpoints | Fickling, manual |
| Business Logic | 25-45% | High | Workflow step-skipping, race conditions on credit/quota operations | Turbo Intruder, custom scripts |
| CSRF Bypass | 10-20% | Medium | Missing `@csrf_protect` (Django), SameSite absent | Burp CSRF PoC generator |
| Auth Bypass | 20-30% | High | Weak session management, password reset flaws, 2FA skip | Manual, Hydra |

Priority: SSTI → SQLi → Business Logic → Auth Bypass → Pickle RCE → CSRF

## APIs (REST/GraphQL)

| Vulnerability | Likelihood | Impact | Testing Focus | Tools |
|---|---|---|---|---|
| BOLA/IDOR | 30-50% | Critical | Object ID substitution across users, Autorize automation | Burp (Autorize), manual |
| Business Logic / Race Conditions | 25-50% | Critical | Concurrent requests on check-write operations, step skipping | Turbo Intruder, Python threading |
| JWT Issues | 25-45% | High | Algorithm confusion, expired token reuse, weak key cracking | jwt_tool, Burp Suite |
| GraphQL Introspection Abuse | 20-35% | Medium | Exposed schema, batch query BOLA, field-level auth failures | InQL, GraphQL Voyager |
| Mass Assignment | 10-25% | High | `{"role":"admin"}` in JSON payloads, extra fields on update | Manual, Burp Repeater |
| Rate-Limiting Bypass | 15-30% | Medium | IP rotation via headers, account distribution | Burp Intruder, custom scripts |

Priority: BOLA → Business Logic → JWT → Mass Assignment → GraphQL → Rate Limiting

## LLM/AI-Integrated Applications

| Vulnerability | Likelihood | Impact | Testing Focus | Tools |
|---|---|---|---|---|
| Indirect Prompt Injection | 30-50% | Critical | Attacker-controlled content retrieved by agent and treated as instruction | Manual crafted content, OOB |
| Direct Prompt Injection | 20-40% | High | System prompt override via user input, jailbreaks affecting tool use | Manual |
| Tool/Function Abuse | 15-30% | Critical | Model caused to call tools with attacker-chosen parameters | Manual, observe tool call logs |
| Data Poisoning (RAG) | 10-25% | High | Attacker-controlled documents in retrieval corpus influencing model output | Manual document injection |
| Insecure Output Handling | 20-35% | High | Model output rendered unsanitised (XSS, SQLi downstream) | Manual, inspect output sinks |

Priority: Indirect Prompt Injection → Tool Abuse → Insecure Output → Direct Injection → RAG Poisoning

Testing AI-integrated applications requires tracing the full pipeline: what does the model
retrieve, what can the attacker influence in that retrieval, and what actions does the model
take with its output? Test at the end of the chain, not just the input endpoint.

## Cloud Pipelines (CI/CD, Serverless)

| Vulnerability | Likelihood | Impact | Testing Focus | Tools |
|---|---|---|---|---|
| Secrets in Logs/Env | 30-50% | Critical | AWS keys, DB credentials in build logs, exposed environment variables | TruffleHog, GitLeaks |
| Over-Permissive IAM | 25-45% | High | Wildcard policies, privilege escalation via `iam:PassRole` | Pacu, AWS CLI, PMapper |
| CI/CD Code Injection | 15-30% | Critical | Malicious PRs triggering pipelines, dependency confusion, runner compromise | Manual review, Semgrep |
| Serverless SSRF | 10-25% | High | Lambda/Cloud Function reaching metadata API for credentials | Burp Collaborator, manual |
| Unsecured Storage | 20-40% | Medium | Public S3 buckets, misconfigured Azure blobs, open GCS buckets | S3 scanners, manual |

Priority: Secrets → IAM → CI/CD Injection → SSRF → Storage

See [cloud notes](../../cloud/notes/index) for full coverage of cloud-specific attack paths.
