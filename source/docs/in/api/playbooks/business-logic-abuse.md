# Playbook: Business logic abuse

This playbook covers the full sequence for identifying and exploiting business logic flaws in
an API. It connects workflow mapping through to documented economic or operational impact.
Business logic abuse requires no special payloads and leaves no anomalous signatures. The
test looks like a slightly obsessive user.

## Objective

Identify workflows that produce unintended outcomes when used in sequences, at scale, out of
order, or in combinations the developer did not test. Produce findings expressed as economic
or operational impact.

## Prerequisites

- Completed endpoint and schema mapping from the discovery runbooks.
- At least two test accounts at different privilege levels.
- An account with a resource worth racing: a credit balance, a quota, a one-time coupon.
- Burp Suite with Turbo Intruder for race condition testing.
- Python with `requests` and `threading` for concurrent testing.
- A workflow diagram or notes on what the API is designed to do.

## Phase 1: Map the workflows

Before testing anything, map the workflows the API supports. A workflow is a sequence of calls
that produces a meaningful outcome: a purchase, a refund, a withdrawal, a privilege grant.

For each workflow, identify:

- The required sequence of calls and the state each produces.
- The terminal state and what it enables or unlocks.
- Any time-limited conditions (token expiry, session state, order status windows).
- What data persists between calls and where it is stored (session, database, token claims).

Prioritise workflows whose terminal states have the highest value: financial credit, elevated
permissions, resource access, verified identity. These are the targets.

## Phase 2: Step-skipping

Test whether every step in a workflow is enforced, or whether the terminal state is reachable
by jumping directly to the final call.

For a checkout flow with three steps, skip to step three without completing the prior steps.
For a verification flow that requires an email confirmation, call the verified-state endpoint
directly. For a refund flow that requires the order to be in "delivered" status, call the
refund endpoint when the order is in "processing" status.

If the terminal state is reachable without the intermediate steps, those steps are frontend
enforcement only. Document the skipped steps and the outcome achieved.

Also test reversal: can a completed workflow be re-run from an intermediate step? If an order
moves from "pending" to "confirmed" to "shipped", can the "confirmed" endpoint be called again
after the order has shipped? Workflow states that can be re-entered often have unintended
consequences.

## Phase 3: Race the checks

For any workflow that performs a check and then a write, test whether the gap between the
check and the write is exploitable.

Identify the check-write pair. Common patterns:

- Check balance, then deduct.
- Check coupon validity, then mark as redeemed.
- Check quota remaining, then record usage.
- Check order status, then issue refund.

### Balance and quota races

Send concurrent requests that each pass the balance or quota check before any of them writes
the deduction. Using HTTP/2 single-packet attack via Turbo Intruder:

1. Capture the target request in Burp Suite and send to Turbo Intruder.
2. Load the `race-single-packet-attack.py` template.
3. Set twenty concurrent requests against the same endpoint.
4. Run the attack and look for multiple `200 OK` responses where only one should succeed.

If more than one request returns success, the check was not atomic. Document the number of
successful requests and calculate the economic impact: if the balance was ten units and five
requests succeeded, the over-spend is forty units.

### Coupon and token races

Request a password reset or generate a single-use coupon. Send concurrent redemption requests
with the same token:

```python
import threading, requests

TOKEN = "YOUR_TOKEN"
COUPON = "TESTCOUPON"
ENDPOINT = "https://target.com/api/v1/redeem"

def redeem():
    r = requests.post(ENDPOINT,
                      headers={"Authorization": f"Bearer {TOKEN}",
                               "Content-Type": "application/json"},
                      json={"coupon": COUPON})
    print(r.status_code, r.text[:120])

threads = [threading.Thread(target=redeem) for _ in range(15)]
for t in threads: t.start()
for t in threads: t.join()
```

If more than one thread returns success, the token invalidation is not atomic.

## Phase 4: Double-spend and refund loops

For any workflow that includes a reversal or refund operation, test whether the reversal can
be triggered multiple times for the same original transaction.

### Concurrent refund requests

Send two refund requests for the same order simultaneously, before the first can be processed
and the order status updated:

```bash
# Run both in parallel
curl -s -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN" &
curl -s -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN" &
wait
```

If both return `200`, the refund processed twice. Check the credit balance to confirm the
double credit was applied.

### Refund after status change

Complete the workflow past the point where refunds should be available, then attempt a refund:

```bash
# Advance the order to a terminal state
curl -X POST https://target.com/api/v1/orders/ORDER_ID/complete \
  -H "Authorization: Bearer TOKEN"

# Then request a refund
curl -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN"
```

A successful refund after completion indicates that the status transition does not correctly
gate the refund operation.

## Phase 5: Chain for unintended outcomes

Identify pairs and sequences of endpoints that, used together, produce an outcome neither
was designed to enable alone.

### Permission accumulation

Call the role or permission assignment endpoint multiple times with overlapping roles. Verify
whether the combined permissions exceed what any individual role grants:

```bash
# Assign first role
curl -X POST https://target.com/api/v1/users/self/roles \
  -H "Authorization: Bearer TOKEN" \
  -d '{"role": "support_read"}'

# Assign second role with overlapping scope
curl -X POST https://target.com/api/v1/users/self/roles \
  -H "Authorization: Bearer TOKEN" \
  -d '{"role": "billing_read"}'

# Test whether combined permissions unlock access not available individually
curl https://target.com/api/v1/admin/export \
  -H "Authorization: Bearer TOKEN"
```

### Password reset chain to account takeover

Request a reset link for an account. Change the account's email address to an attacker-controlled
address. Then use the original reset link (sent to the original address):

1. Trigger `POST /api/v1/auth/reset-password` for Account A.
2. Change Account A's email to attacker@attacker.com via `PUT /api/v1/profile`.
3. Use the reset token from the original email to set a new password.

If the original token is still valid after the email change, the token is not bound to the
current email address. Account takeover using only authenticated, documented API calls.

### Export and import reprocessing

Upload content through the upload endpoint (which applies strict validation). Trigger a
processing step on it. Export the result. The processing step may apply looser validation
because it treats the uploaded content as already-validated:

1. Upload a document via `POST /api/v1/documents`.
2. Trigger processing via `POST /api/v1/documents/DOC_ID/process`.
3. Export via `GET /api/v1/documents/DOC_ID/export`.

Review the exported output for content that the upload validation should have blocked. This
is particularly relevant for format conversions (DOCX to PDF, XML to JSON) where the
conversion engine parses the input rather than just passing it through.

## Phase 6: Measure the detection gap

After mapping what is achievable, determine how much of it is detectable.

Gradually escalate behaviour and observe at what point the system responds: rate limiting
kicks in, an account is flagged, a CAPTCHA appears, a session is invalidated. Document the
threshold at which each control triggers.

The question is not whether controls exist. It is how much abuse is possible before they
trigger, and how much of that abuse leaves no audit trail.

For findings with economic impact, calculate the realistic gain: how many concurrent requests
can exploit the race window, how many times can the loop run before detection, what is the
total value extractable before any alert fires?

## Output

- Workflow state machines with vulnerabilities mapped to specific transitions.
- Step-skipping findings: which steps are frontend-only.
- Race condition findings: the over-spend or over-redemption achievable, with economic
  impact.
- Double-spend findings: refund or reversal operations that are not idempotent.
- Chaining findings: the full call sequence and the unintended terminal state.
- Detection gap measurement: the maximum abuse achievable before any control triggers.

## Runbooks

- [Business logic testing](../runbooks/business-logic.md)
- [Race condition testing](../runbooks/race-conditions.md)

## Techniques

- [Business logic abuse](../notes/business-logic.md)
- [Race conditions](../notes/business-logic.md)
