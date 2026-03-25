# Detect API recon and abuse

API logs are often the least-monitored logs in an organisation's stack. Application logs capture
business events. Infrastructure logs capture network activity. API-level logs, which capture the
specific operations individual identities performed against specific resources, are frequently
collected but rarely analysed. Detection requires defining what anomalous API usage looks like and
alerting on it rather than waiting for an incident to prompt a log review.

## What to instrument

### Request logging

Every API request should produce a structured log entry containing at minimum: the timestamp,
the authenticated identity (not just the session token, but the resolved user or service identity),
the HTTP method, the full request path including query parameters, the response status code, the
response time, and the source IP address.

Client IP should be recorded from the actual network connection, not from the `X-Forwarded-For`
header, unless the infrastructure guarantees that header is set by a trusted proxy. Recording
the header value unvalidated means an attacker can write whatever they want into the client IP
field of your logs.

### Schema and introspection query logging

For GraphQL APIs, log the full query body, not just the operation name. Introspection queries,
batched queries, and unusually complex queries are all visible in the query body. An operation
named `userProfile` that contains an introspection query is not a normal user profile request.

Log the resolved query depth and complexity for each request if query analysis is in place. A
request that hits the maximum configured depth limit is worth investigating even if it was blocked.

## Detection patterns

### Endpoint enumeration

Endpoint enumeration generates a characteristic pattern: requests to many different paths from
the same source in a short time window, with a high proportion returning `404` or `405` responses.

Alert on: more than thirty distinct paths requested from the same authenticated identity or source
IP within five minutes, where more than half return `404` or `405`.

Wordlist-based brute-forcing also produces a burst of requests with no meaningful session state:
no cookies, no vary in the User-Agent, a consistent pattern in the timing of requests.

### Authentication probing

Password spraying against an API authentication endpoint produces repeated `401` responses across
different usernames from the same source. Rate limiting prevents brute force; it does not prevent
detection.

Alert on: more than ten `401` responses across more than three distinct usernames from the same
source IP within fifteen minutes.

Monitor also for successful authentications that follow a pattern of prior failures. A session
that produces many `401` responses before a `200` is either a legitimate user who forgot their
password or an attacker who guessed correctly.

### Unusual authorised access patterns

BOLA exploitation looks different from normal usage. A user who normally accesses their own
resources will not normally request resources identified by other users' IDs.

Alert on: an authenticated identity that requests more than ten distinct resource IDs in a single
resource type within a minute, where those IDs are not related to their own account history. This
pattern indicates either automated enumeration or BOLA testing.

For admin endpoints, alert on any access attempt by an identity that does not have an
administrative role, regardless of whether the attempt succeeded or returned `403`.

### Schema extraction attempts

GraphQL introspection queries are recognisable by the `__schema` field in the query body. They
are legitimate in development environments. In production, they are either a misconfiguration
(introspection should be disabled) or an active recon attempt.

Alert on any `__schema` or `__type` query in a production environment. If introspection is
correctly disabled, the request will fail, but the attempt is still worth knowing about.

Field suggestion exploitation (querying unknown fields to extract schema information via error
messages) is harder to detect because the individual queries look like malformed requests. Alert
on: an identity that generates more than twenty field validation errors within a minute.

### Token misuse and replay

API tokens used from a new geographic location, a new ASN, or a new device fingerprint after
a period of consistent usage may indicate token theft. Alert on tokens used simultaneously from
locations that are geographically inconsistent with simultaneous use.

For short-lived tokens, alert on tokens used after their stated expiry time. This indicates either
a clock skew issue (investigate) or a validation bypass (investigate urgently).

### Bulk data access

Legitimate users access data one record at a time or in small pages. A session that downloads
hundreds or thousands of records via repeated paginated requests is either a legitimate bulk
export (which should be tracked and authorised) or data exfiltration via the API.

Alert on: more than five hundred data records accessed by a single identity within one hour,
where no bulk export operation was explicitly authorised for that session.

## Behavioural detection

Technical attack patterns (enumeration, injection, schema extraction) are detectable by
signature. Business logic abuse is not. Each individual call is authenticated, authorised,
and within documented parameter ranges. No individual request triggers an alert.

Detecting business logic abuse requires a model of what normal workflows look like and
the ability to identify deviations in sequence, frequency, and outcome.

Workflow sequence monitoring: define the expected order of calls for high-value workflows
(checkout, refund, password reset, privilege grant). Alert on sessions that reach a terminal
state by an unexpected path, such as a refund endpoint called without a prior order confirmation.

Outcome monitoring: monitor the outputs of high-value operations rather than just the requests.
If a user's credit balance increases or an account receives a refund, record it. Alert on
accounts that receive more refunds than purchases, or whose balance exceeds the expected
ceiling without a corresponding top-up event.

Velocity on business operations: a user who triggers twenty password reset requests in an hour
is not a forgot-my-password scenario. A user who redeems fifteen coupons in a session is not
a legitimate customer. Set velocity thresholds on business operations separately from
authentication rate limits.

Concurrent request patterns: legitimate users do not send twenty simultaneous requests to
the same endpoint. Alert on bursts of identical or near-identical requests arriving within
a one-second window from the same authenticated identity.

## Time-to-detect measurement

Detection controls are not binary. The useful question is not whether a control exists but
how much damage is possible before it triggers.

For each detection pattern defined, measure the threshold: how many events, over what time
window, are required to produce an alert? Then calculate what is achievable within that window.
If rate limiting triggers after one hundred requests per minute and a race condition requires
twenty simultaneous requests, the race is exploitable many times over before any control fires.

During testing, document the detection gap: the amount of abuse achievable before any alert
or control triggers. This should be expressed as a business outcome (twenty fraudulent refunds,
forty units of over-spent balance, ten coupon redemptions from one code) rather than a
request count.

If detection gaps are large, the finding is not just the exploitable vulnerability but the
absence of detection that would bound the damage.

## Log aggregation and correlation

API logs are most useful when correlated with authentication events and network logs.

A sequence of: authentication from a new location, followed by schema enumeration, followed by
high-volume object access, followed by bulk record download, is an attack chain. Each event in
isolation may be below an alerting threshold. Together they tell a clear story.

Feed API logs into the SIEM alongside authentication and network events. Define correlation rules
that look for this sequence, not just the individual events. Set a time window of six hours to
catch slow, deliberate enumeration that stays below rate limits.

Extend the same correlation approach to business logic: a session that maps workflow steps,
then tests them out of order, then sends concurrent requests to a payment endpoint is telling
a story. The individual events look like exploration and retries. The sequence looks like
targeted abuse.
