# Fuzzing APIs

Fuzzing sends unexpected, malformed, or boundary-testing input to API endpoints to find cases where
the application behaves in unintended ways. In API testing, fuzzing is less about crashing the
server and more about finding validation gaps: fields that accept values they should reject, inputs
that trigger different code paths, and parameters that produce information disclosure in error
responses.

## What fuzzing reveals

Input validation failures expose themselves through inconsistent responses: a parameter that
accepts `1` but crashes on `1.5` is not validating its input type. A search field that returns
different data for `test' OR 1=1--` than for `test` is passing input to a SQL query.

Excessive data exposure appears when fuzzing reveals fields in responses that are not documented
and should not be accessible. Some APIs return the full object from the data layer and rely on the
frontend to display only the appropriate fields; fuzzing with different content types or accept
headers sometimes bypasses that filtering.

Logic flaws appear when unexpected input values produce outcomes that the developer did not
anticipate: negative quantities, past dates, zero-value prices, extremely long strings, and
boundary values around integer limits all find different code paths.

## What to fuzz

Parameter values are the primary target: string fields with injection payloads, numeric fields
with boundary values, ID fields with other users' identifiers. All of these are covered in the
injection and BOLA runbooks.

Parameter names are also worth fuzzing on write endpoints. Arjun and Param Miner discover
undocumented parameters that the API accepts but does not advertise.

Content type and encoding changes sometimes reveal different code paths. An endpoint that accepts
`application/json` may also accept `application/x-www-form-urlencoded` and process it differently.
A GraphQL endpoint that requires `Content-Type: application/json` may also respond to
`Content-Type: application/graphql`.

HTTP methods are worth fuzzing on every endpoint. An endpoint that only documents `GET` may
also respond to `POST`, `PUT`, or `DELETE`.

## Runbooks

- [REST API attack chain](../playbooks/rest-api.md) — fuzzing in Phase 5
- [Injection testing](../runbooks/injection.md)
- [Rate limit testing and bypass](../runbooks/rate-limit-bypass.md)
