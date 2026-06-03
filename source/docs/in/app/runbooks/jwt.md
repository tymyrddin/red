# Runbook: JWT attacks

JSON Web Tokens carry their own claims and a signature that is supposed to make those claims
tamper-evident. Most JWT findings come from a verifier that trusts something it has no reason
to: an attacker-chosen algorithm, an attacker-supplied key, or a signature it never checks. This
runbook is the deep-dive companion to the JWT phase in the authentication runbook, working
through each verification flaw in turn.

## Prerequisites

- A valid token captured during the recon or authentication pass.
- Burp Suite with the JWT Editor extension, or jwt_tool on the command line.
- The token's decoded header and payload, and the endpoint that reflects privilege
  (an admin panel or a `GET /my-account` style response works well as an oracle).

## Phase 1: Find and decode tokens

Search proxy history for the `eyJ` prefix that marks a base64url-encoded JWT header:

```
"[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*"
```

Decode the header and payload. Note the `alg`, any `kid`, `jku`, or `jwk` header, and the
claims that carry identity (`sub`, `role`, `is_admin`, `email`). Confirm the token is
actually used for an access decision before spending time on it: a token that changes
nothing when removed is not worth attacking.

## Phase 2: Missing or flawed signature verification

The cheapest wins come from a verifier that does not check the signature at all, or checks
it only when present.

- Send the token with the payload modified (for example `sub` set to an admin user) and the
  signature left intact. If access changes, the signature is not being verified.
- Set the `alg` header to `none` and strip the signature entirely (keep the trailing dot).
  A verifier that honours `none` accepts the unsigned token.

```
jwt_tool TOKEN -X a    # alg:none variants
```

## Phase 3: Weak signing key

When the token uses HMAC (HS256), the signature is only as strong as the secret. Brute force
it offline against a wordlist:

```
hashcat -a 0 -m 16500 TOKEN /usr/share/wordlists/jwt.secrets.list
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

A recovered secret lets arbitrary tokens be forged. Re-sign a modified payload with it and
replay.

## Phase 4: Header injection (jwk, jku, kid)

These attacks make the verifier trust a key the attacker controls.

- jwk: embed a self-generated public key in the token's `jwk` header. A verifier that uses
  the embedded key rather than its own trusted key accepts a token signed with the matching
  private key.
- jku: point the `jku` header at an attacker-hosted JWK Set. If the verifier fetches keys
  from that URL without restricting it to a trusted origin, it verifies against the attacker's
  key. The `jku` value is also an SSRF probe in its own right.
- kid: the `kid` header selects which key to use. Where it feeds a file lookup, try path
  traversal to a predictable file (`../../../../dev/null` yields an empty key, so an empty
  HMAC secret signs the token). Where it feeds a query, test for SQL injection returning a
  known value as the key.

## Phase 5: Algorithm confusion (RS256 to HS256)

When tokens are signed with RSA (RS256) and the public key is obtainable, a verifier that
does not pin the algorithm can be tricked into verifying an HS256 token using the RSA public
key as the HMAC secret.

1. Obtain the public key. Many servers expose it at a standard JWK Set endpoint:

```
curl https://target.com/jwks.json
curl https://target.com/.well-known/jwks.json
```

2. Convert the JWK to PEM (the JWT Editor's New RSA Key dialogue imports the JWK and exports
   PEM; jwt_tool can derive it too). Where no key is published, two captured tokens are enough
   to recover the modulus.
3. Forge the token: set `alg` to `HS256`, modify the identity claim, and sign with HMAC using
   the PEM public key as the secret.

```
jwt_tool TOKEN -X k -pk public.pem
```

4. Replay against the privileged endpoint. Success confirms the server is verifying the
   attacker's HS256 signature with its own public key.

## Output

- Which verification flaw applies (unverified signature, alg:none, weak key, header
  injection, algorithm confusion).
- The forged token and the privileged action it enabled.
- For jku and kid findings, any secondary SSRF or injection reached through the header.

## Techniques

- [JWT attacks](../techniques/jwt.md)
- [Authentication and session testing](auth-testing.md)

## Counter moves

Runbook: JWT attacks is what this page works through. Pinning the algorithm, verifying
signatures against a trusted key, and rejecting attacker-supplied key material are the
counters. Defenders' notes on this are under [the surface designed to be accessible](https://blue.tymyrddin.dev/docs/counter/api/).
