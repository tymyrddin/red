# Runbook: Workflow and business logic testing

Business logic testing asks what happens when the application is used in sequences, at scale,
or in combinations the developer did not test. There are no payloads to detect and no
anomalous HTTP methods. Every request is authenticated and within the documented parameter
ranges. Detection requires understanding what normal looks like.

The approach shifts from "is this endpoint vulnerable?" to "what can someone achieve using
this system over time?"

## Prerequisites

- Complete endpoint and workflow understanding from the recon runbook.
- At least two test accounts at different privilege levels.
- Burp Suite Pro with Turbo Intruder.
- Python with `requests` and `threading` for concurrent tests.
- A workflow diagram or notes on what the application is designed to do.

## Phase 1: Map workflows as state machines

Before testing anything, map every multi-step workflow the application supports. A workflow
is a sequence of requests that produces a meaningful terminal state: a purchase, a
withdrawal, a privilege grant, an account verification.

For each workflow, document:
- The endpoint called at each step and the HTTP method.
- What state transition each step produces (what changes in the application's data model).
- What data carries across steps (session values, query parameters, hidden form fields).
- What the terminal state enables.

Prioritise workflows whose terminal states have the most value: financial credit, elevated
permissions, account verification, subscription activation.

## Phase 2: Step skipping

Test whether every step in a workflow is enforced server-side, or whether the terminal
state is reachable by calling the final endpoint directly:

```bash
# A checkout flow normally requires: add to cart → apply discount → confirm payment
# Test: call the confirmation endpoint directly without the prior steps
curl -X POST https://target.com/checkout/confirm \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART_ID", "payment_method": "SAVED_CARD"}'
```

If the order confirms without prior steps, those steps are frontend enforcement only.

Test also the reverse: calling steps in a different order. A refund endpoint that requires
the order to be in "delivered" state may behave unexpectedly when called while the order is
in "processing" state.

## Phase 3: Parameter manipulation across steps

Multi-step flows often carry values from one step to the next in a cookie, session variable,
or hidden field. Test whether these carried values can be substituted.

In a checkout flow where the price is set in step one and confirmed in step three, test
whether the price in the step-three request is independently validated:

```bash
# Step 1: add item, price is set server-side
# Step 2: observe the price carried in the session or form field
# Step 3: submit with a modified price
curl -X POST https://target.com/checkout/confirm \
  -H "Authorization: Bearer TOKEN" \
  -d "price=0.01&cart_id=CART_ID"
```

Similarly, test whether quantity values, discount codes, and shipping costs are recalculated
server-side at the confirmation step, or whether they trust the values set earlier.

## Phase 4: Race conditions

For any workflow that performs a check followed by a write, test the gap between check and
write. Classic patterns:

- Check balance, then deduct.
- Check coupon validity, then mark as redeemed.
- Check quota remaining, then record usage.
- Check order status before issuing refund.

Send twenty concurrent requests using Turbo Intruder's single-packet attack. If more than
one returns success where only one should, the check was not atomic:

```python
# Turbo Intruder script for race condition testing
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=20,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    table.add(req)
```

Or with Python threading for direct control:

```python
import threading, requests

TOKEN = "YOUR_TOKEN"
ENDPOINT = "https://target.com/redeem"

def redeem():
    r = requests.post(ENDPOINT,
                      headers={"Authorization": f"Bearer {TOKEN}"},
                      json={"coupon": "TESTCOUPON"})
    print(r.status_code, r.text[:80])

threads = [threading.Thread(target=redeem) for _ in range(15)]
for t in threads: t.start()
for t in threads: t.join()
```

## Phase 5: Multi-user interactions

Test the application's behaviour when two users interact with the same resource
simultaneously or in sequence.

Shared object access: can Account B interact with Account A's in-progress workflow?
If Account A has a cart open, can Account B add to it, change its state, or trigger
its completion?

Concurrent modification: what happens when two users modify the same object simultaneously?
Does the application handle concurrent writes correctly, or does one user's write silently
overwrite the other's?

Privilege grant timing: if Account A is granted a role that is then revoked, do existing
sessions remain valid? Test whether session tokens carry privilege state or whether
privilege is re-checked on each request.

## Phase 6: Measure the detection gap

After identifying what is achievable, determine how much of it is detectable.

Escalate behaviour gradually and observe when (if) any control responds: rate limiting
activates, an account is flagged, a CAPTCHA appears. Document the threshold.

The question is not whether controls exist but how much abuse is achievable before they
trigger, and what that amounts to in economic or operational terms.

## Output

- Workflow state machines with vulnerabilities mapped to transitions.
- Step-skipping findings with demonstrated terminal state achieved.
- Parameter substitution findings: price, quantity, or status manipulation.
- Race condition findings with achieved over-spend or over-redemption and economic impact.
- Multi-user interaction findings.
- Detection threshold measurements.

## Techniques

- [Application logic errors](../techniques/business.md)
- [Race conditions](../techniques/race.md)
- [Broken access control](../techniques/acl.md)
