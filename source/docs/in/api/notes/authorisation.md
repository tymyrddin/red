# API authorisation

Authorisation determines what an authenticated identity is permitted to do. In APIs, authorisation
fails in two distinct ways: at the object level and at the function level. Both are consistently
among the highest-impact API vulnerabilities because they require no special tooling to exploit,
only a valid account and the ability to modify a request parameter.

## Broken object level authorisation (BOLA)

BOLA occurs when an API endpoint accepts a resource identifier as input but does not verify that
the authenticated caller is permitted to access that specific resource. The check confirms the
caller is authenticated; it does not confirm the resource belongs to them.

The impact is direct: an attacker with any valid account can read, modify, or delete resources
belonging to every other user. The identifier does not need to be guessable: sequential integers,
UUIDs, and even opaque hashes are all equally vulnerable when the authorisation check is absent.

BOLA is the OWASP API Security Top 10's number one finding, and has been for several editions,
because it is extremely common and the fix requires discipline at every endpoint rather than a
single configuration change.

## Broken function level authorisation (BFLA)

BFLA occurs when a low-privilege user can invoke an operation that should require higher privileges.
Admin operations, bulk exports, user management functions, and configuration endpoints are the
typical targets. The check confirms the caller is authenticated and has a valid role; it does not
confirm the role is sufficient for the specific operation.

BFLA is often found alongside BOLA. Applications that miss authorisation checks at the object level
frequently also miss them at the function level, because both stem from the same root cause:
authorisation was not systematically enforced at the function that handles the request.

## Why authorisation fails in APIs

Web frameworks make it easy to authenticate a request at the routing level and assume that is
sufficient. It is not. A route guard that confirms the request carries a valid token does not
confirm the resource in the URL belongs to the token holder.

Microservice architectures introduce additional risk: a service that receives a forwarded request
from a trusted internal service may skip authorisation entirely on the assumption that the calling
service already checked. When that assumption is wrong, every resource is accessible to any service
that can reach the API.

## Runbooks

- [BOLA and BFLA testing](../runbooks/bola-bfla.md)
