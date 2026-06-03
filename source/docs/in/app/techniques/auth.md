# Authentication vulnerabilities

Authentication verifies who is calling the application. The token that authentication
issues is the identity for everything that follows: access control decisions, audit logs,
rate limit buckets, and business logic checks all depend on the session being genuine.
The attack surface spans from the initial credential check through to the expiry of the
last issued token.

## Mechanisms and their failure modes

Password-based authentication fails in consistent ways: usernames that can be enumerated
because error messages differ between valid and invalid usernames, password policies that
accept credentials common enough to spray, and rate limiting that is absent, bypassable,
or only applied per-IP rather than per-account.

Session tokens are the persistence layer of authentication. A token stored without the
`HttpOnly` flag is readable from JavaScript and extractable via any XSS. A token without
`SameSite=Strict` is submitted by the browser with cross-origin requests, enabling CSRF.
A predictable token is directly forgeable. A token that is never invalidated server-side
persists even after logout.

JWT tokens introduce algorithm-level attack surface. An API that validates the algorithm
declared in the token header rather than enforcing a specific one can be tricked into
accepting a `none`-signed token, a token with a symmetric signature that uses the server's
own public key as the secret, or a token signed with a crackable weak key.

OAuth and SSO implementations are frequently misconfigured rather than broken at the
protocol level. Redirect URI validation that permits substrings, wildcards, or
directory traversal allows authorisation code theft. Missing or unvalidated `state`
parameters enable CSRF against the flow. Dynamic client registration without restriction
allows an attacker to register a client and then abuse it.

Password reset flows introduce a distinct attack surface. A reset token that is sent to the
email address but constructed from the `Host` header in the reset request can be poisoned
by modifying that header: the token arrives at the victim's address but points to an
attacker-controlled server. A token that does not expire, is not invalidated on use, or
is not bound to the account's current email address at the time of redemption is reusable
or transferable.

## Modern authentication abuse

Valid sessions obtained through legitimate means are not automatically constrained to their
intended use. A token issued by a mobile application may carry broader permissions than the
mobile UI exposes. Long-lived tokens (persistent login cookies, OAuth refresh tokens with
rolling expiry) accumulate value over time, granting access to data that did not exist when
they were issued.

Multi-factor authentication reduces but does not eliminate authentication attack surface.
The OTP endpoint requires its own rate limiting: without it, a six-digit code space is
enumerable in under a million requests. The 2FA step is sometimes skipped entirely when
the session management allows a partially-authenticated token to access resources meant to
sit behind the second factor.

Service-to-service authentication in microservice architectures is frequently weaker than
user-facing authentication. Internal APIs may accept requests from any source on the same
network, or rely on a shared secret that is the same across all services. An SSRF
vulnerability that can reach internal services may bypass authentication entirely.

## Indicators

Differences in application behaviour between valid and invalid usernames, credentials, or
token values. Rate limiting that is absent, per-IP (bypassable with header manipulation),
or applied only on the authentication endpoint but not on downstream credential verification
steps.

JWT tokens with weak algorithms, crackable keys, or unvalidated claims. Session tokens that
are predictable, missing security flags, or not invalidated on logout.

Password reset flows that are host-header-dependent, produce long-lived or reusable tokens,
or do not bind the token to the current email address.

OAuth flows with overly permissive redirect URI validation, missing state parameter
enforcement, or dynamic client registration available without restriction.

## Variants

The families here are username enumeration (through differing responses, response timing, or
account-lock behaviour), broken brute-force protection (per-IP blocks, multiple credentials
per request, or brute force routed through the password-change endpoint), two-factor
weaknesses (a simple skip, broken logic, or brute-forced codes), session-token attacks
(brute-forcing a stay-logged-in cookie, offline cracking), and password-reset logic flaws
including host-header poisoning.

## Runbooks

- [Authentication and session testing](../runbooks/auth-testing.md)

## Counter moves

Authentication vulnerabilities is the case here. These come back to the same answers: validated input, encoded output, server-side authorisation, and patched dependencies. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
