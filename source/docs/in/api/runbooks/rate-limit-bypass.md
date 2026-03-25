# Runbook: Rate limit testing and bypass

Rate limits are one of the few controls that slow automated API attacks: credential stuffing,
enumeration, and brute force all depend on making many requests quickly. When rate limits are
absent or bypassable, attacks that would otherwise be impractical become routine.

## Objective

Determine whether rate limits exist for sensitive endpoints and whether they can be bypassed.
Document the threshold, the enforcement mechanism, and any bypass methods that work.

## Prerequisites

- Target API endpoints, particularly authentication, OTP verification, and search endpoints.
- Burp Suite Intruder or ffuf for automated request generation.
- A pool of IP addresses or a VPN for IP rotation testing.

## Phase 1: Confirm rate limit existence

Test whether any limit is enforced before attempting bypasses.

Send fifty requests to the authentication endpoint in quick succession and observe the responses:

```bash
for i in $(seq 1 50); do
  response=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    https://target.com/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@target.com","password":"attempt'$i'"}')
  echo "Request $i: $response"
done
```

Document when the response changes. A `429 Too Many Requests` response with a `Retry-After`
header is a properly implemented rate limit. A continued `401` with no change means no rate
limiting is in place.

Test the following endpoint types separately, as they often have different (or no) limits:

- Login and authentication
- Password reset request
- OTP and MFA code verification
- Account registration
- Search and enumeration endpoints
- Password change

## Phase 2: IP-based bypass

Most rate limits track the source IP address. If the API uses the `X-Forwarded-For` or
`X-Real-IP` header to identify the client without validating that it was set by a trusted proxy,
the limit can be bypassed by rotating the header value:

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: 10.0.0.$((i % 254 + 1))" \
    -H "Content-Type: application/json" \
    -X POST https://target.com/api/v1/auth/login \
    -d '{"email":"target@target.com","password":"attempt'$i'"}'
done
```

Also test these headers, as different application stacks check different ones:

```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
```

## Phase 3: Account-based distribution

If IP rotation does not work, distribute requests across multiple accounts. OTP brute force
targeting a specific account from one identity may be rate limited, but sending one request
per account per minute across many accounts stays below per-account limits while still making
progress.

This is relevant for:
- Password reset code enumeration (one request per code value per account)
- Account enumeration (one request per username, from a single IP)
- Any enumeration where the limit is applied per target account rather than per source

## Phase 4: Parameter encoding and case variation

Some rate limit implementations normalise input inconsistently, counting differently for variant
representations of the same value:

```bash
# Test whether encoded variants are counted separately
curl -X POST https://target.com/api/v1/login \
  -d '{"email":"user%40target.com","password":"test"}'  # URL-encoded @

curl -X POST https://target.com/api/v1/login \
  -d '{"email":"USER@target.com","password":"test"}'  # uppercase

curl -X POST https://target.com/api/v1/login \
  -d '{"email":" user@target.com","password":"test"}'  # leading space
```

If these variants reset the counter, the effective rate limit is multiplied by the number of
valid variants.

## Phase 5: Endpoint and method variation

Test whether the rate limit applies to the specific path or to the underlying function. Some
APIs apply limits to the URL path literally, meaning `/api/v1/login` and `/api/v1/login/`
are counted separately. Some apply it per HTTP method, so switching between `POST` and `PUT`
(where both are accepted) resets the counter.

```bash
# Test path trailing slash
curl -X POST https://target.com/api/v1/login/

# Test path case variation
curl -X POST https://target.com/API/v1/login
curl -X POST https://target.com/api/V1/login
```

## Phase 6: Timing-based bypass

If the rate limit resets on a predictable schedule (per minute, per hour), requests can be
paced to stay within the limit while still making progress over time. Determine the reset
interval by reaching the limit, waiting, and confirming when requests succeed again.

With a limit of ten requests per minute and a reset at the start of each minute, 600 attempts
per hour is achievable without ever triggering a lockout, which is sufficient to enumerate
a six-digit OTP within a few hours.

## Output

- Rate limit status for each tested endpoint: present or absent.
- Threshold and reset interval for any limits found.
- Bypass methods confirmed to work, with the specific headers or techniques used.
- Practical impact: how many attempts per hour are achievable with the bypass.

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
