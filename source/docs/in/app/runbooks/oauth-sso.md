# Runbook: OAuth and SSO attacks

OAuth and OpenID Connect move authentication out to an identity provider that several
applications trust. The token exchange is sound on paper; the findings live in the
integration, where redirect handling, state validation, and scope are left loose. This
runbook works through the recurring failures in the authorisation code and implicit flows.

## Prerequisites

- An account at the identity provider and an account at the client application.
- Burp Suite with the proxy capturing the full OAuth dance (authorisation request, redirect
  back, token exchange).
- An attacker-controlled host that can receive a redirect or host a page, for the token-theft
  variants.

## Phase 1: Map the flow

Capture every request from the initial `/authorize` call to the point where the client
issues its own session. Record the `response_type` (a `token` value means the implicit flow,
`code` the authorisation code flow), the `redirect_uri`, the `scope`, the `state`, and any
`code_challenge`. The parameters that the client fails to bind tightly are the ones worth
attacking.

## Phase 2: redirect_uri validation

The redirect URI delivers the code or token, so loose validation hands it to an attacker.
Starting from the exact registered value, try:

```
https://client.com.attacker.com        # suffix that contains the allowed host
https://attacker.com?x=client.com       # allowed host as a parameter
https://client.com/../../attacker.com   # path traversal past prefix matching
https://client.com/callback/../redirect # extra path the validator did not anticipate
```

A provider that accepts any of these sends the authorisation code to the attacker's
endpoint, which is then exchanged for a token. Where the open redirect is one step removed,
chain it: a permitted `redirect_uri` that itself bounces through an open redirect on the
client leaks the code in the `Referer` or the location.

## Phase 3: implicit flow and token leakage

In the implicit flow the access token lands in the URL fragment. Test whether an attacker who
controls or influences the landing page can read it: a token delivered to a page that loads
attacker-controlled script, or reflected through an open redirect, is stealable. A proxy page
on the client that forwards the fragment to another origin is the same class of bug.

For clients that accept a token or code the attacker obtained for their own account, test
forced linking: complete the linking step with the victim, so the attacker's social account
becomes bound to the victim's profile.

## Phase 4: state and CSRF

The `state` parameter is the flow's CSRF defence. Remove it, or replay a fixed value, and see
whether the client still completes the login. A client that does not generate a fresh random
state per request, or does not check the returned value, allows login CSRF: the victim is
silently logged into the attacker's identity, so anything they then save lands in the
attacker's account.

## Phase 5: PKCE downgrade

For public clients using PKCE, test whether the `code_verifier` is genuinely checked. Capture
a flow with a known `code_challenge`, then exchange the code with a missing or different
verifier. Acceptance means PKCE adds no protection and an intercepted code is still usable.

## Phase 6: SSRF via OpenID dynamic client registration

Where the provider supports dynamic client registration, several registration fields take
URLs the server later fetches (`logo_uri`, `jwks_uri`, `sector_identifier_uri`). Register a
client with one of these pointing at an internal address or a Collaborator payload, trigger
the fetch, and watch for the out-of-band interaction. This reaches the identity provider's
own network rather than the client's.

## Output

- The loose parameter (redirect_uri, state, scope, code_verifier) and the access it yielded.
- Any stolen code or token and the account takeover it enabled.
- SSRF reached through registration metadata, with the internal target confirmed.

## Techniques

- [Single sign-on security](../techniques/sso.md)
- [Authentication and session testing](auth-testing.md)
- [SSRF](../techniques/ssrf.md)

## Counter moves

Runbook: OAuth and SSO attacks is the case here. Strict redirect-URI matching, per-request
state, enforced PKCE, and allowlisted registration URLs are the counters. Defenders' notes on
this are under [the surface designed to be accessible](https://blue.tymyrddin.dev/docs/counter/api/).
