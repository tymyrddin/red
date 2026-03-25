# Runbook: BOLA and BFLA testing

Broken Object Level Authorisation (BOLA) and Broken Function Level Authorisation (BFLA) are
consistently the most impactful API vulnerabilities. BOLA lets one user access another user's
data by manipulating resource identifiers. BFLA lets a low-privilege user invoke operations that
should require higher privileges. Both stem from the API failing to verify that the authenticated
identity actually has permission to perform the requested operation on the requested resource.

## Objective

Identify every endpoint that fails to verify the relationship between the authenticated identity
and the resource being accessed or the operation being performed.

## Prerequisites

- Complete endpoint list from the discovery runbook.
- At least two test accounts at different privilege levels (user A, user B, and if possible an
  admin account), all within the authorised scope.
- Burp Suite configured as a proxy.
- The Autorize Burp extension for automated BOLA detection.

## BOLA testing methodology

### What BOLA looks like

A BOLA vulnerability exists when account A can read, modify, or delete a resource that belongs
to account B, by substituting account B's resource identifier into a request authenticated as
account A. The API processes the request because the token is valid; it fails to check whether
the resource belongs to the token holder.

### Identifier collection

First, collect resource identifiers across both test accounts. Log in as account A and perform
every operation that creates or references a resource. Record every identifier that appears:
in URL paths, query parameters, request bodies, and response bodies.

Common identifier patterns:
- Integer IDs: `/api/v1/orders/1234`
- UUIDs: `/api/v1/users/550e8400-e29b-41d4-a716-446655440000`
- Base64-encoded IDs: decoded often reveal internal sequential numbers
- Compound identifiers: `/api/v1/accounts/123/documents/456`

Log in as account B and record account B's identifiers for the same resources.

### A-B testing

With account A's token and account B's resource identifiers, make requests to every relevant
endpoint:

```bash
# Account A's token, account B's resource ID
curl -H "Authorization: Bearer TOKEN_A" \
  https://target.com/api/v1/users/USER_B_ID/profile

curl -H "Authorization: Bearer TOKEN_A" \
  https://target.com/api/v1/orders/ORDER_B_ID

curl -H "Authorization: Bearer TOKEN_A" \
  https://target.com/api/v1/documents/DOCUMENT_B_ID/download
```

A `200` response returning account B's data is a confirmed BOLA vulnerability.

### A-B-A testing for write operations

For write and delete operations, use A-B-A testing to confirm the vulnerability without
permanently modifying account B's data:

1. Record the current state of account B's resource (A step, baseline).
2. Make the modification request authenticated as account A, targeting account B's resource
   (B step, the attack).
3. Verify the resource was modified using account B's credentials (A step, confirmation).
4. Restore the original state using account A's token (cleanup).

```bash
# Step 1: record current state
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/v1/profile > original_state.json

# Step 2: modify as account A
curl -X PUT -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"email": "probe@attacker.com"}' \
  https://target.com/api/v1/users/USER_B_ID/profile

# Step 3: verify modification occurred
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/v1/profile

# Step 4: restore (using account A's access to set back the original value)
curl -X PUT -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d @original_state.json \
  https://target.com/api/v1/users/USER_B_ID/profile
```

### Automating with Autorize

Autorize (Burp Suite extension) automates BOLA detection by replaying every request with a
different user's token and comparing the responses.

Configuration:
1. Set the low-privilege token in Autorize's "Auth Header" field.
2. Browse the application as the high-privilege user.
3. Autorize replays every request with the low-privilege token and flags responses where the
   status code and body match the original high-privilege response.

Review all flagged responses. Autorize produces false positives for public endpoints; filter
these by cross-referencing with the known-public endpoint list.

## BFLA testing methodology

### What BFLA looks like

A BFLA vulnerability exists when a low-privilege user can invoke an operation that should require
higher privileges, such as administrative functions, bulk data exports, or user management
operations. Unlike BOLA, the resource identifier may be the user's own; the issue is the
operation itself being accessible to the wrong role.

### Function discovery

Identify functions that are intended to be restricted. These are often:
- Endpoints with `admin`, `manage`, `internal`, or `system` in the path
- Endpoints that appear in the OpenAPI spec with an `admin` or `manager` role requirement
- Endpoints observed in traffic only when logged in as a higher-privilege account
- Endpoints discovered via brute-forcing that return `403` for the regular user account

### Role-based access testing

Test each restricted endpoint with the low-privilege token:

```bash
# Try accessing an admin endpoint with a regular user token
curl -H "Authorization: Bearer TOKEN_USER" \
  https://target.com/api/v1/admin/users

curl -H "Authorization: Bearer TOKEN_USER" \
  https://target.com/api/v1/admin/settings

curl -H "Authorization: Bearer TOKEN_USER" \
  https://target.com/api/v1/reports/full-export
```

A `200` response means BFLA. A `403` means the check is in place for that endpoint.

Also test HTTP method switching. An endpoint that returns `403` on `DELETE` may accept `POST`
with a `_method=DELETE` parameter, or accept the `X-HTTP-Method-Override: DELETE` header:

```bash
curl -X POST -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer TOKEN_USER" \
  https://target.com/api/v1/admin/users/TARGET_USER_ID
```

### Privilege escalation via parameter injection

Test whether a low-privilege user can elevate their own permissions by injecting role or
permission parameters into requests that modify their own account:

```bash
# Attempt to set role to admin during profile update
curl -X PUT -H "Authorization: Bearer TOKEN_USER" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "role": "admin", "is_admin": true}' \
  https://target.com/api/v1/profile
```

Then retrieve the profile to see if the role was accepted:

```bash
curl -H "Authorization: Bearer TOKEN_USER" https://target.com/api/v1/profile
```

This is the mass assignment variant of BFLA: the API accepts fields it should ignore.

## Output

- List of endpoints vulnerable to BOLA with evidence of cross-account data access.
- List of endpoints vulnerable to BFLA with evidence of privilege escalation.
- HTTP method override findings.
- Mass assignment findings where role or permission parameters were accepted.
- All test operations performed, with timestamps and account identifiers used.

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
