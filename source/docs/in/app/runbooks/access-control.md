# Runbook: Access control testing

Access control testing determines whether the application correctly enforces who can access
what. The two main failure modes are horizontal access control failures (accessing another
user's resources at the same privilege level) and vertical failures (accessing resources or
functions that require higher privilege). Both require systematic testing, not spot checks.

## Prerequisites

- Complete endpoint inventory from the recon runbook.
- Two test accounts: Account A and Account B at the same privilege level.
- A third account at a higher privilege level if available.
- Burp Suite Pro with Autorize extension.
- A test account with enough resource history that A and B have distinct object IDs.

## Phase 1: Unauthenticated access sweep

Strip authentication from every endpoint in the Burp site map and replay. This is the
fastest, highest-yield check. Any endpoint that returns data or performs an action without
authentication is an immediate critical finding.

Configure Burp's "match and replace" to remove the `Authorization` header and the session
cookie simultaneously, then use the site map's "send all items" function to replay all
captured requests with no credentials.

## Phase 2: Horizontal IDOR testing

IDOR vulnerabilities allow one user to access another user's objects by substituting
identifiers. Test every endpoint that references a resource by ID.

### Collect identifiers

As Account A, collect all resource IDs visible in the application: user IDs, order IDs,
document IDs, message IDs, file names in upload paths. Record them in a table alongside
the resource type and endpoint.

### A-to-B testing

Using Account B's session, request each resource that belongs to Account A:

```bash
# Account B attempts to read Account A's order
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/v1/orders/ORDER_A_ID

# Account B attempts to read Account A's profile
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/v1/users/USER_A_ID

# Account B attempts to read Account A's messages
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/v1/messages/MESSAGE_A_ID
```

Also test write operations: can Account B modify or delete Account A's objects?

### A-B-A cleanup testing

For write-access IDOR, test whether modifications made by Account B are visible to Account A.
This confirms the write succeeded rather than just returning a `200` without effect:

1. Account A creates a resource: note its ID and current state.
2. Account B modifies the resource via the IDOR endpoint.
3. Account A retrieves the resource: if it reflects Account B's modification, the IDOR is confirmed.

### Autorize automation

Configure Autorize with Account B's session cookies and headers. Browse the application as
Account A. Autorize replays every request with Account B's credentials and flags responses
that return the same data. Review every flagged item.

## Phase 3: Vertical access control testing

Test whether lower-privilege accounts can access higher-privilege functions.

Collect all endpoints that return `403` for your standard test account. These are the
endpoints worth attacking. For each one:

```bash
# Test the endpoint with a low-privilege token
curl -H "Authorization: Bearer LOW_PRIV_TOKEN" https://target.com/api/v1/admin/users

# Test HTTP method override
curl -X POST \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer LOW_PRIV_TOKEN" \
  https://target.com/api/v1/admin/users/1

# Test case and path variation
curl -H "Authorization: Bearer LOW_PRIV_TOKEN" https://target.com/API/V1/Admin/Users
curl -H "Authorization: Bearer LOW_PRIV_TOKEN" https://target.com/api/v1/admin/users/
```

Also test URL-encoded path traversal in admin paths:

```
/api/v1/normal/../admin/users
/api/v1/%61dmin/users
/api/v1/admin;.../users
```

## Phase 4: Function-level access control

Test whether specific functions within an endpoint are accessible at lower privilege levels.

For an account update endpoint, test adding `role`, `is_admin`, `permissions`, or
`account_type` fields to the request body (mass assignment). If these fields are reflected
in subsequent responses, the authorisation check is missing at the function level:

```bash
curl -X PUT -H "Authorization: Bearer LOW_PRIV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "role": "admin", "is_admin": true}' \
  https://target.com/api/v1/profile
```

Also test whether endpoint responses include fields that the current privilege level should
not see: internal flags, other users' data, system configuration, admin tokens.

## Phase 5: Multi-step access control

Multi-step workflows sometimes enforce access control on step one but not on subsequent steps.

Test whether completing a privileged operation by navigating directly to the final step
works without completing the earlier steps:

1. Map the full multi-step flow for a privileged operation.
2. Attempt to call the final step endpoint directly using a low-privilege token.
3. If the final step succeeds, the intermediate steps are enforcement only in the frontend.

Also test step repetition: in a flow where a step should execute exactly once, call it again
after completing the workflow. An order confirmation step that can be replayed, a payment
step that can be re-triggered, or a role grant that can be called multiple times may all
produce unintended outcomes.

## Output

- Unauthenticated endpoints that return data or perform actions.
- IDOR findings: which resource types are accessible cross-account, with demonstrated impact.
- Vertical access control bypass: which admin or elevated-privilege endpoints are reachable.
- Mass assignment findings: which extra fields are accepted and what they change.
- Multi-step bypass findings: which workflow steps are frontend-only.

## Techniques

- [Broken access control](../techniques/acl.md)
- [IDOR](../techniques/idor.md)
