# Runbook: Business logic testing

Business logic testing maps what the API is designed to do and then systematically attempts to
produce unintended outcomes using only legitimate, authenticated calls. There are no payloads to
detect, no anomalous HTTP methods, and no signatures to match. The test looks like a slightly
obsessive user.

## Objective

Identify workflows that produce unintended outcomes when used in sequences, at scale, out of order,
or in combinations the developer did not test. Produce findings expressed as economic or operational
impact rather than CVSS scores.

## Prerequisites

- Complete endpoint and schema understanding from the discovery runbooks.
- At least two test accounts at different privilege levels.
- An account with enough balance, credits, or quota to meaningfully test limits.
- Burp Suite for session management and request replay.
- Turbo Intruder for race condition testing (covered in the race conditions runbook).
- A workflow diagram: what the API is supposed to do and in what order.

## Phase 1: Workflow mapping

Before testing anything, map the workflows the API supports. A workflow is a sequence of API
calls that produces a meaningful outcome: a purchase, a refund, a withdrawal, a content
publication, a privilege grant.

For each workflow, document:
- The required sequence of calls
- The state transitions each call produces
- What data persists between calls (session, database records, tokens)
- What the terminal state looks like and what it enables

Draw the state machine if it helps. The vulnerabilities live in the transitions and the edges.

Identify the workflows with the most valuable terminal states: financial credit, elevated
permissions, resource access, verified status. These are the highest-priority targets.

## Phase 2: Step skipping and sequence manipulation

Test whether every step in a workflow is actually enforced, or whether the terminal state is
reachable by skipping intermediate steps.

For a multi-step checkout flow:

```bash
# Step 1 would normally be: add to cart
# Step 2: apply discount code
# Step 3: confirm payment
# Test: call Step 3 directly, without completing Step 1 or 2
curl -X POST https://target.com/api/v1/orders/confirm \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART_ID", "payment_method": "STORED_CARD"}'
```

If the order confirms without the prior steps, the prior steps are purely frontend enforcement.

Test calling steps in a different order than intended. A refund endpoint that requires an order
to exist in "delivered" status may produce unexpected behaviour if called when the order is in
"processing" status, because the developer tested the happy path and not the edge.

## Phase 3: Quota and limit exploitation

Map every limit the API enforces: rate limits, credit limits, quota limits, usage caps, free tier
restrictions. Test each at the boundary and on the boundary.

### Credit and balance tests

If the API deducts from a balance on use, test concurrent deductions from the same balance. Send
two requests simultaneously that each check the balance and attempt to deduct:

```python
import threading, requests

TOKEN = "YOUR_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def spend():
    r = requests.post("https://target.com/api/v1/spend",
                      headers=HEADERS,
                      json={"amount": 100})
    print(r.status_code, r.json())

# Fire both simultaneously
t1 = threading.Thread(target=spend)
t2 = threading.Thread(target=spend)
t1.start(); t2.start()
t1.join(); t2.join()
```

If both requests succeed, the deduction was not atomic.

### Free tier and quota bypass

Test whether paid features are enforced at the API or only in the frontend. Call the paid
endpoints directly with a free-tier token:

```bash
curl -H "Authorization: Bearer FREE_TIER_TOKEN" \
  https://target.com/api/v1/export/full  # should require paid tier
```

Test whether the quota resets correctly. If a per-day limit resets at a predictable time (midnight
UTC, for example), test whether requests sent immediately before the reset and immediately after
can produce more than the daily allowance.

## Phase 4: Refund and reversal abuse

For any workflow that includes a reversal or refund operation, test whether the reversal can be
triggered multiple times for the same original transaction, and whether the reversal can be
triggered in a different state than the developer intended.

### Double refund test

```bash
# Request a refund for order ORDER_ID
curl -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN"

# Immediately request again before the first is processed
curl -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN"
```

If both return `200`, the refund was processed twice.

### Refund after status change

Test whether a refund can be requested after the order has reached a state where refunds
should no longer be available:

```bash
# Complete the order
curl -X POST https://target.com/api/v1/orders/ORDER_ID/complete \
  -H "Authorization: Bearer TOKEN"

# Then request a refund on the completed order
curl -X POST https://target.com/api/v1/orders/ORDER_ID/refund \
  -H "Authorization: Bearer TOKEN"
```

## Phase 5: Chaining for unintended outcomes

Identify pairs and sequences of endpoints that, combined, produce an outcome neither endpoint
was designed to enable alone.

### Permission accumulation

Call a role assignment or permission grant endpoint multiple times with overlapping roles:

```bash
# Assign role A
curl -X POST https://target.com/api/v1/users/self/roles \
  -d '{"role": "support_read"}' \
  -H "Authorization: Bearer TOKEN"

# Assign role B with overlapping permissions
curl -X POST https://target.com/api/v1/users/self/roles \
  -d '{"role": "billing_read"}' \
  -H "Authorization: Bearer TOKEN"

# Test whether combined permissions exceed what either role grants individually
curl https://target.com/api/v1/admin/export \
  -H "Authorization: Bearer TOKEN"
```

### Export and import reprocessing

Upload a document, trigger a processing step on it, then export the result. The processing step
may not validate the uploaded content as strictly as the initial upload endpoint, because the
input is treated as already-validated internal data:

```bash
# Upload content with a hidden payload
curl -X POST https://target.com/api/v1/documents \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@crafted_document.docx"

# Trigger processing
curl -X POST https://target.com/api/v1/documents/DOC_ID/process \
  -H "Authorization: Bearer TOKEN"

# Export and review the processed output for unexpected content
curl https://target.com/api/v1/documents/DOC_ID/export \
  -H "Authorization: Bearer TOKEN" -o output.pdf
```

## Phase 6: Anomaly threshold testing

Determine at what point the system notices. This is the detection gap measurement.

Gradually escalate behaviour and observe when (if) a response changes: rate limiting kicks in,
an account gets flagged, a CAPTCHA appears, a session is invalidated. Document the threshold.

The question is not whether controls exist. It is: how much abuse is possible before they trigger?

## Output

- Workflow state machine for each tested workflow with vulnerabilities mapped to transitions.
- Step-skipping findings: which workflow steps are frontend-only.
- Atomic operation failures: concurrent requests that produce double-spend or double-refund.
- Quota bypass findings with exploitation method and economic impact.
- Chaining findings with the full call sequence and the unintended outcome.
- Anomaly threshold measurements: what level of abuse is achievable before detection.

## Playbooks

- [Business logic abuse](../playbooks/business-logic-abuse.md)
