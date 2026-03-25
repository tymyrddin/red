# Rate limiting

Rate limits are a control applied to API endpoints to restrict how many requests a caller can make
in a given time window. Without them, automated attacks that require many requests (credential
stuffing, OTP brute force, enumeration) are limited only by network speed.

## What is being protected

Authentication endpoints require rate limiting more urgently than data retrieval endpoints, because
a credential attack needs many attempts against the same target. A six-digit OTP without rate
limiting can be exhausted in under a second. A PIN reset endpoint with no limit can be brute-forced
in minutes.

Enumeration endpoints also benefit from rate limiting: account existence checks, username lookups,
and search functions that reveal whether a specific value exists in the database all become
enumeration tools without limits.

## Common failure modes

Rate limits are applied per IP address and bypassed by rotating the IP or spoofing forwarded
headers. When the limit is applied based on the `X-Forwarded-For` header value without validating
that the header was set by a trusted proxy, any caller can set it to an arbitrary value.

Limits are applied per endpoint path and bypassed by using alternative representations of the
same path: trailing slashes, case variation, URL encoding, or method substitution.

Limits reset on a predictable schedule (every minute, on the minute) and can be exploited by
pacing requests to just below the threshold on each interval.

Limits apply globally to the endpoint and not per target account, making distributed attacks
(one attempt per account, across many accounts) invisible to the rate limiting control.

## Relationship to other controls

Rate limiting slows attacks but does not prevent them. It is most effective when combined with
account lockout (which stops per-account brute force after a threshold), anomaly detection
(which flags unusual patterns across accounts), and proper entropy in secrets and codes (which
makes exhaustion impractical even without a rate limit).

## Runbooks

- [Rate limit testing and bypass](../runbooks/rate-limit-bypass.md)
