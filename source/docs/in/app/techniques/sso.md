# Single sign-on security

SSO concentrates authentication into a single identity provider that multiple applications
trust. The security benefit is that a well-implemented identity provider is better maintained
than a dozen individual application login systems. The risk is that a misconfiguration in
the SSO layer affects every application that depends on it, and the integration surface
between each application and the identity provider introduces attack surface of its own.

Modern SSO deployments primarily use OAuth 2.0 and OpenID Connect for consumer and SaaS
applications, and SAML for enterprise federation. Each protocol has distinct attack patterns.

## OAuth 2.0 and OpenID Connect

OAuth authorisation code flows grant a client application an authorisation code that it
exchanges for tokens. The redirect URI is the delivery mechanism for that code. If the
identity provider's redirect URI validation is insufficiently strict, the authorisation code
can be delivered to an attacker-controlled endpoint.

Common redirect URI validation failures: substring matching that accepts `https://target.com.attacker.com`, path
prefix matching that accepts `https://target.com/../../../attacker.com`, and open redirect
chains where the permitted redirect URI itself redirects to an attacker-controlled location.

The `state` parameter is the CSRF protection for the OAuth flow. A client that does not
generate a cryptographically random state value per authorisation request, or that does not
validate the returned state value before exchanging the code, is vulnerable to login CSRF:
an attacker can cause a victim to authenticate with the attacker's identity in the client
application.

PKCE (Proof Key for Code Exchange) is required for public clients and prevents authorisation
code interception attacks. An implementation that accepts a code exchange without a valid
`code_verifier`, or that accepts any value as the verifier regardless of the original
`code_challenge`, provides no protection against code theft.

OAuth token scope defines what the access token permits. Applications that request broader
scope than they need, or that store tokens with full scope in client-accessible storage,
create a surface where token theft produces consequences beyond the intended use.

## SAML

SAML assertions are XML documents signed by the identity provider and consumed by the
service provider. The service provider must validate the signature before acting on the
assertion's contents.

Signature wrapping attacks exploit XML parsers that validate the signature over one part
of the document but act on a different part. If the assertion contains two elements and
the signature covers only one, an attacker who can add an unsigned element to the document
may be able to inject assertion content that the signature does not cover but the service
provider's parser selects. The signature is technically valid; the assertion contents are
attacker-controlled.

XML parsers that fail to validate signatures entirely, or that validate the signature but
accept a `None` signature algorithm, allow forged assertions. Test by modifying the
`NameID` in a captured assertion and replaying it with the signature removed or replaced.

SAML replay: assertions include a one-time ID and an expiry timestamp. A service provider
that does not track used assertion IDs allows a captured, valid assertion to be replayed
after the original user has ended their session.

## Cross-account session confusion

SSO systems that serve multiple tenants or organisations sometimes fail to enforce tenant
isolation at the token level. A token issued for one tenant should only be accepted by
resources belonging to that tenant. If the service provider validates the token's signature
but not its audience or tenant binding, a valid token from one tenant may grant access to
another.

This is more common in SaaS applications that use a shared identity provider across all
customers. The `aud` claim in an OIDC token, or the recipient restriction in a SAML
assertion, is the binding. Absent or unvalidated, a token is portable across tenants.

## Portswigger lab writeups

- [Authentication bypass via OAuth implicit flow](../burp/oauth/1.md)
- [Forced OAuth profile linking](../burp/oauth/2.md)
- [OAuth account hijacking via redirect_uri](../burp/oauth/3.md)
- [Stealing OAuth access tokens via an open redirect](../burp/oauth/4.md)
- [SSRF via OpenID dynamic client registration](../burp/oauth/5.md)
- [Stealing OAuth access tokens via a proxy page](../burp/oauth/6.md)

## Runbooks

- [Authentication and session testing](../runbooks/auth-testing.md)
