# Evasion techniques

API security controls, WAFs, input validation, and rate limits are obstacles to testing rather
than absolute barriers. Evasion techniques modify how payloads are delivered without changing
what they do, to avoid pattern-based detection while still triggering the underlying vulnerability.

## WAF evasion

Web application firewalls block requests that match known attack patterns. They match against
the decoded, normalised form of the input, but the matching is imperfect, and bypass techniques
exploit the gap between how the WAF interprets input and how the backend processes it.

String terminators (`%00`, null bytes) cause some parsers to truncate input before the malicious
portion while passing the truncated value to the WAF for inspection.

Case variation changes the surface of the payload without changing its meaning to a SQL parser or
template engine: `SELECT` and `SeLeCt` are equivalent to the database but may not both match a
WAF signature.

Encoding transforms the payload into a representation the WAF may not normalise: URL encoding
(`%27` for `'`), double URL encoding (`%2527`), HTML entity encoding, and Unicode normalisation
all produce the same character after decoding.

Comment insertion breaks up recognised patterns: `SEL/**/ECT` in SQL is equivalent to `SELECT`
after the SQL parser strips comments.

Combining techniques multiplies the bypass surface. A double-encoded, commented, mixed-case
payload may pass a WAF that would block any single technique.

## Bypassing input validation

Server-side input validation often checks the format of input before the application uses it.
When the validation and the processing are not using the same normalisation, bypasses exist.

Type confusion exploits languages that coerce types: an API that validates a JSON field as a
string may pass validation with `"1"` and then cast it to an integer for database lookup,
where an injected value in string form becomes executable.

Parameter pollution sends the same parameter multiple times. Some frameworks take the first
value, some take the last, and some concatenate them. When the validator and the processor
disagree, the validated value is not the processed value.

Whitespace and boundary characters in unexpected positions sometimes cause parsers to treat
input differently: a trailing newline in a header value, a space before an operator in a query,
or a zero-width character inside a keyword.

## Pacing to avoid rate limits

See the rate limit runbook for techniques specific to bypassing per-request throttling.

For WAF-based rate limiting (blocking after a number of malicious-looking requests from one
source), distribute requests across time rather than rotating IPs. Slow, deliberate testing
with delays between requests avoids triggering volume-based WAF rules while still covering
the attack surface.

## Runbooks

- [Rate limit testing and bypass](../runbooks/rate-limit-bypass.md)
- [Injection testing](../runbooks/injection.md)
