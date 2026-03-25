# API authentication

API authentication verifies who is calling the API. Unlike web application authentication, which
typically uses a single session cookie mechanism, APIs use a variety of token formats and protocols,
each with its own failure modes. The attack surface is not just the login endpoint: it is the entire
token lifecycle from issuance to validation to expiry.

## Common mechanisms

JWT (JSON Web Token) encodes identity claims in a signed, base64-encoded structure. The signature
algorithm, signing key strength, and validation logic all present attack surface. Algorithm confusion
attacks exploit APIs that accept whatever algorithm the token header declares rather than enforcing
a specific one. A token signed with `none` (no signature) should always be rejected; many
implementations do not reject it.

API keys are long-lived credentials issued to a client application or user. They accumulate in
repositories, documentation, and configuration files. Unlike session tokens, they frequently have
no expiry and no revocation audit trail.

OAuth grants third-party applications access to a user's resources without sharing the user's
credentials. Weaknesses appear in the redirect URI validation, the state parameter implementation,
and the scope of tokens issued. A misconfigured redirect URI allows authorisation code theft.

Basic authentication sends credentials with every request, base64-encoded but not encrypted.
Acceptable only over TLS; still common in internal APIs where TLS is assumed.

## Why API authentication breaks

Token validation is often incomplete. An API may verify that a JWT is well-formed and not expired
without verifying the signature, or may verify the signature with the wrong key. Endpoint-level
authentication checks are sometimes present on some endpoints and missing from others.

Credentials reach unintended places. API keys in JavaScript bundles are visible to every user of
the application. Keys committed to version control are visible to anyone with access to the
repository, including forks made before the commit was removed from history.

Rate limiting on authentication endpoints is inconsistent. Without it, automated credential testing
is only limited by network speed.

## Valid-session abuse

A valid, legitimately obtained token is not necessarily constrained to its intended use. If the
token grants more scope than the application exposes through its interface, the additional scope
is accessible directly to anyone who can obtain the token.

Tokens issued for mobile applications sometimes carry broader permissions than mobile UI surfaces
expose. Tokens obtained via OAuth consent may grant access to resources the user did not
explicitly intend to authorise, because the requested scope was broader than the consent screen
described.

Long-lived tokens (API keys with no expiry, refresh tokens with rolling windows) accumulate
value over time. A token obtained early in a session or via a passive source may still be valid
weeks or months later, granting access to data that did not exist when the token was issued.

## Service-to-service trust

Internal APIs that communicate between microservices frequently rely on network-level trust
rather than cryptographic authentication. A service inside the perimeter may be trusted to
call any other internal service with no token required, or with a shared secret that is the
same across all services and environments.

These trust assumptions are exploitable when an attacker gains any foothold inside the
perimeter, or when an internal-facing API is inadvertently exposed externally. An API that
validates tokens carefully for external traffic may have a separate internal endpoint that
accepts requests from any source on the same network without authentication.

SSRF vulnerabilities that reach internal APIs are particularly valuable in this context: the
SSRF does not need to extract data directly if it can call an internal service that operates
without authentication.

## Runbooks

- [Authentication testing](../runbooks/auth-testing.md)
