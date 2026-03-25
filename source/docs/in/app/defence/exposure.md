# Reducing web application attack surface

Defence starts with reducing what is exploitable. Every control below addresses a class of
vulnerability that appears consistently in web application testing. None of them is
sufficient alone; together they raise the cost of exploitation significantly.

## Input handling

Parameterised queries (prepared statements) eliminate SQL injection for database calls.
This is not an input validation approach: it separates the query structure from the data
at the driver level, so no input value can change the query's meaning regardless of its
content.

Server-side template rendering should use auto-escaping engines and should never pass
user input directly into `render()`, `eval()`, or template string construction. If a
feature genuinely requires dynamic template content, constrain what is dynamic rather than
sanitising the input.

File and URL inputs fed to outbound HTTP clients (image loaders, webhook handlers, document
importers) must be validated against an explicit allowlist of permitted schemes, hosts, and
ports. Block loopback addresses and link-local ranges (169.254.0.0/16, ::1) at the
validation layer, not as an afterthought.

XML parsers must be configured to disable external entity processing and DTD loading
explicitly. The safe configuration is not the default in most libraries:

```python
# Python lxml: disable external entities
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)

# Java SAXParser
factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
```

## Output and response handling

Stack traces and detailed error messages must not reach the client in production. Error
responses should use a generic message with a correlation ID that maps to the full detail
in server-side logs. An error page that reveals the ORM type, database schema, or
framework version is a discovery aid.

HTTP responses should include security headers on every page:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

The Content-Security-Policy is the most impactful XSS mitigation. A policy that disallows
inline scripts and external script sources forces XSS payloads to find a script source
the policy permits, which is significantly harder.

## Authentication and session hardening

Session cookies must carry `HttpOnly`, `Secure`, and `SameSite=Strict` (or at minimum
`SameSite=Lax`). `HttpOnly` prevents JavaScript from reading the cookie, limiting XSS
impact. `Secure` prevents transmission over HTTP. `SameSite=Strict` prevents the cookie
from being sent with cross-origin requests, eliminating most CSRF attack scenarios.

JWT implementations must use an explicit algorithm allowlist rather than accepting whatever
algorithm the token header declares. The `none` algorithm must be rejected. Asymmetric
algorithms (RS256, ES256) are preferable to symmetric ones (HS256) for tokens validated
across multiple services. Key rotation must be implemented, not planned.

Password reset tokens and one-time codes must have short expiry times (fifteen minutes),
be bound to the email address at the time of issuance, and be invalidated after first use.

## Access control

Access control must be enforced server-side on every request, not assumed from the UI flow.
A deny-by-default approach, where every endpoint requires authentication unless explicitly
marked public, prevents the common pattern of an endpoint that was "internal" during
development and accidentally left open.

Mass assignment must be prevented with explicit allowlists at the model or serialiser layer,
not by stripping fields from user input. If a field should never be set by a client, it
should not be assignable regardless of what the client sends.

Separate privileged operations from the main application surface. Admin functionality
served from a separate subdomain or path prefix that is only accessible from specific
network sources is harder to test and harder to abuse.

## Business logic

Shared-state operations must use atomic database transactions or application-level locks.
A check-and-write that reads a value and then updates it without holding a lock is
exploitable with concurrent requests. Idempotency keys on financial operations prevent
double-spend from race conditions and duplicate submissions.

Workflow state transitions should be validated server-side at every step, not only at the
start and end. If a refund is only valid when an order is in "delivered" status, that status
check must happen at the refund endpoint, not be implied by the UI flow that precedes it.
