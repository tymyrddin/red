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
the session management allows a partially-authenticated token to access resources that
should require the second factor.

Service-to-service authentication in microservice architectures is frequently weaker than
user-facing authentication. Internal APIs may accept requests from any source on the same
network, or rely on a shared secret that is the same across all services. An SSRF
vulnerability that can reach internal services may bypass authentication entirely.

## What to look for

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

## Portswigger lab writeups

- [Username enumeration via different responses](../burp/auth/1.md)
- [2FA simple bypass](../burp/auth/2.md)
- [Password reset broken logic](../burp/auth/3.md)
- [Username enumeration via subtly different responses](../burp/auth/4.md)
- [Username enumeration via response timing](../burp/auth/5.md)
- [Broken brute-force protection, IP block](../burp/auth/6.md)
- [Username enumeration via account lock](../burp/auth/7.md)
- [2FA broken logic](../burp/auth/8.md)
- [Brute-forcing a stay-logged-in cookie](../burp/auth/9.md)
- [Offline password cracking](../burp/auth/10.md)
- [Password reset poisoning via middleware](../burp/auth/11.md)
- [Password brute-force via password change](../burp/auth/12.md)
- [Broken brute-force protection, multiple credentials per request](../burp/auth/13.md)
- [2FA bypass using a brute-force attack](../burp/auth/14.md)

## Runbooks

- [Authentication and session testing](../runbooks/auth-testing.md)
