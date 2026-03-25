# Playbook: REST API attack chain

This playbook connects the API runbooks into an operational sequence for a REST API engagement.
It describes the decision points that determine which vulnerabilities to pursue and in what order,
from the first passive look at the API through to documented findings.

## Objective

Identify exploitable vulnerabilities in a REST API: authentication weaknesses, authorisation
bypass, data exposure, and injection, in a sequence that moves from lower-risk discovery to
targeted exploitation.

## Prerequisites

- Target API base URL and scope documentation.
- At least one valid account within the engagement scope, ideally at multiple privilege levels.
- Burp Suite Pro with Autorize and Param Miner extensions.
- Postman for collection management.
- jwt_tool, Arjun, Kiterunner.
- A clean testing environment separate from any production accounts you manage.

## Phase 1: Passive recon and surface mapping

Start without sending any requests to the API directly. Spend time here; it consistently produces
findings that active testing misses.

Review passive sources in this order:

1. GitHub and GitLab repositories: look for the API specification, configuration files, and
   committed credentials. Record any API keys, tokens, or base URLs found.
2. JavaScript bundles served by the frontend application: extract all API paths.
3. Wayback Machine: retrieve historical URLs and identify deprecated endpoints.
4. Documentation paths: check all common specification paths without authentication.

If an OpenAPI specification is found, import it into Postman and review it before doing anything
else. Look immediately for: operations with no authentication requirement in the spec, operations
that accept `additionalProperties`, and internal or administrative operations.

If API keys or tokens are found in passive sources, validate them immediately:

```bash
curl -H "Authorization: Bearer FOUND_TOKEN" https://target.com/api/v1/me
```

A valid token from a passive source is the highest-priority finding. Document it, determine its
scope, and proceed to authorisation testing with it before it is rotated.

## Phase 2: Active endpoint and parameter discovery

Route all application traffic through Burp Suite. Use the application as every available account
role, exercising every feature. Let the proxy build the site map.

After the manual walkthrough, run Kiterunner against the API base path to find undocumented
endpoints:

```bash
kr scan https://target.com/api -w routes-large.kite -x 20
```

For every discovered endpoint, run Arjun to find undocumented parameters:

```bash
arjun -u https://target.com/api/v1/users -m GET
arjun -u https://target.com/api/v1/orders -m POST
```

Add all discovered endpoints and parameters to the Postman collection.

## Phase 3: Authentication testing

Before testing any authorisation or business logic, confirm the authentication model.

Remove authentication from every endpoint in the collection and observe which ones respond with
data. Any endpoint that returns `200` without authentication is an immediate finding.

If the API uses JWT, decode every token received. Check the algorithm, the claims, and the
expiry. Run jwt_tool to test algorithm confusion:

```bash
jwt_tool TOKEN -X a  # none algorithm
jwt_tool TOKEN -X k -pk server_public_key.pem  # RS256 to HS256 confusion
```

Test whether authentication endpoints have rate limiting. If not, document it and proceed.

## Phase 4: Authorisation testing

With two test accounts (Account A and Account B), run systematic BOLA testing across every
endpoint that references a resource identifier.

Configure Autorize with Account B's token and browse the application as Account A. Review every
flagged response.

For every endpoint that returns Account A's data as Account A, test the same endpoint with
Account B's resource identifiers:

```bash
# Test access to Account B's resources using Account A's token
curl -H "Authorization: Bearer TOKEN_A" https://target.com/api/v1/users/USER_B_ID/orders
curl -H "Authorization: Bearer TOKEN_A" https://target.com/api/v1/documents/DOCUMENT_B_ID
```

After BOLA testing, test BFLA on every endpoint that returns `403` for the low-privilege account.
Also test HTTP method override on any endpoint that shows access control on write methods:

```bash
curl -X POST -H "X-HTTP-Method-Override: PUT" \
  -H "Authorization: Bearer TOKEN_USER" \
  https://target.com/api/v1/admin/config
```

## Phase 5: Input validation and injection

For every endpoint that accepts user input, test the input handling.

### Mass assignment

Add extra fields to request bodies that should not be accepted: `role`, `is_admin`, `permissions`,
`account_type`, `status`. Observe whether they are reflected in subsequent responses.

```bash
curl -X PUT -H "Authorization: Bearer TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "role": "admin", "credits": 99999}' \
  https://target.com/api/v1/profile
```

### Fuzzing

Use Burp Suite Intruder or ffuf to fuzz parameter values. Focus on parameters that:
- Accept identifiers (IDOR risk)
- Accept strings that appear in responses (XSS and injection risk)
- Control pagination or sorting (injection risk in ORDER BY)
- Accept file paths or URLs (path traversal and SSRF risk)

```bash
ffuf -u "https://target.com/api/v1/items?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
  -H "Authorization: Bearer TOKEN_A" \
  -mc 200,500
```

### Rate limit bypass

For any endpoint with rate limiting, test bypass with IP rotation via X-Forwarded-For:

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "Authorization: Bearer TOKEN_A" \
    https://target.com/api/v1/auth/verify-otp \
    -d '{"otp": "'$(printf "%06d" $i)'"}'
done
```

## Phase 6: Behavioural and business logic testing

After technical testing, shift from asking "does this endpoint behave correctly?" to "what
can someone achieve by using this system in sequences the developer did not test?"

Map the workflows the API supports. For each workflow with a high-value terminal state
(financial credit, elevated permissions, resource access), test:

- Step skipping: can the terminal state be reached without completing intermediate steps?
- Sequence manipulation: what happens if steps are called in a different order?
- Concurrent access: does the check-write gap allow multiple simultaneous requests to
  all pass the same condition?

For any endpoint that deducts from a balance, validates a one-time token, or checks a quota,
use Turbo Intruder's single-packet attack to send twenty concurrent requests simultaneously.
If more than one returns success, the check is not atomic.

For refund or reversal endpoints, test whether the same operation can be triggered twice for
the same transaction, either sequentially (if the status update is slow) or concurrently.

Document all findings as economic or operational impact: not "race condition exists" but "an
attacker can spend forty units from a ten-unit balance" or "a single coupon can be redeemed
fifteen times before the system prevents it."

## Phase 7: Evidence collection

For each finding, capture:

- The exact request (method, URL, headers, body) that demonstrates the vulnerability.
- The response showing the impact (data returned, state changed, privilege gained).
- The account identities used (Token A belongs to user X, Token B belongs to user Y).
- The timestamp and source IP of the test request.
- A brief description of the impact: what data is accessible, what operations are possible.

Export the relevant Burp Suite items for each finding. Include the full request and response.

## Techniques

- [API surface discovery](../notes/recon.md)
- [Endpoint discovery](../runbooks/endpoint-discovery.md)
- [Schema analysis](../runbooks/schema-analysis.md)
- [Authentication testing](../runbooks/auth-testing.md)
- [BOLA and BFLA testing](../runbooks/bola-bfla.md)
- [Authorisation](../notes/authorisation.md)
- [Mass assignment](../notes/mass-assignment.md)
- [Evasive techniques](../notes/evade.md)
- [Business logic abuse](../notes/business-logic.md)
- [Business logic abuse playbook](business-logic-abuse.md)
- [Race condition testing](../runbooks/race-conditions.md)
