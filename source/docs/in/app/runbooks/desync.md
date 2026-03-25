# Runbook: HTTP request smuggling and desync

HTTP request smuggling exploits disagreement between the way a front-end proxy and a
back-end server parse the boundaries of HTTP requests. When two servers interpret the same
request differently, one of them treats the trailing bytes as the beginning of the next
request. This allows an attacker to prepend data to another user's request, or to inject
a complete request that the server processes under the attacker's control but attributes
to someone else.

Modern variants extend this to HTTP/2 downgrade scenarios and client-side desync, where
the victim's browser can be caused to make a request that the back-end interprets as
containing an injected prefix.

## Prerequisites

- Burp Suite Pro with Turbo Intruder and HTTP Request Smuggler extension.
- Understanding of the target's reverse proxy stack (nginx, HAProxy, AWS ALB, Cloudflare).
- An OOB detection channel (Burp Collaborator).

## Phase 1: Detect the vulnerability class

Most targets are either CL.TE (front-end uses Content-Length, back-end uses
Transfer-Encoding) or TE.CL (front-end uses Transfer-Encoding, back-end uses
Content-Length).

Run HTTP Request Smuggler (Burp extension) against the target host to automate initial
detection. Review any flagged responses for timing differences or unexpected response data.

### Manual CL.TE timing probe

A CL.TE vulnerability causes the back-end to wait for additional data after the front-end
has already closed the request. This produces a time delay:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

The front-end reads 6 bytes (the chunk terminator `0\r\n\r\n` and `X`) and forwards.
The back-end treats the chunked encoding as definitive: after receiving the `0` chunk, it
waits for the next request. The `X` byte is left in the buffer. If the response is
significantly delayed, CL.TE is likely present.

### Manual TE.CL timing probe

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

1
Z
Q
```

The front-end uses Transfer-Encoding and processes the `1\r\nZ\r\n` chunk, then sees `Q`
and waits for the next chunk. The back-end uses Content-Length (3 bytes: `1\r\n`). The
remaining data is left in its buffer. If the response is delayed, TE.CL is present.

## Phase 2: Confirm with socket reuse

Timing probes can be caused by legitimate network conditions. Confirm with a technique that
produces a detectable second-order effect.

For CL.TE, smuggle a request prefix that produces an anomalous response for the next
request on that connection:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 43
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

Send the request twice on the same connection. If the second response returns `/admin`
content rather than the root page, the prefix was injected into the subsequent request.

## Phase 3: HTTP/2 desync

HTTP/2 uses binary framing and never has CL/TE ambiguity at the HTTP/2 layer. The
vulnerability appears when the HTTP/2 front-end downgrades to HTTP/1.1 when communicating
with the back-end, introducing the ambiguity during translation.

In Burp, set the request to HTTP/2 using the Inspector panel. Test whether injecting a
`Transfer-Encoding: chunked` header into the HTTP/2 request causes the back-end to behave
as it would in a classic TE.CL scenario.

Also test HTTP/2 header injection: some front-ends allow HTTP/2 headers containing newlines
that, when translated to HTTP/1.1, introduce additional headers or split the request.

## Phase 4: Client-side desync

Client-side desync does not require control of the network path between the client and
server. It works when the server itself responds to an initial request in a way that causes
the client's connection to become desynchronised.

Test endpoints that respond to a request with a short response and leave a connection alive.
If the server can be caused to respond without consuming the full request body, the remaining
bytes may be prepended to the victim's next request on the same connection:

```
POST /endpoint HTTP/1.1
Host: target.com
Content-Length: 34

GET /admin HTTP/1.1
X-Ignore: X
```

This requires testing in Burp's browser with repeat-connection mode disabled, so that the
browser reuses connections as a real browser would.

## Phase 5: Attack development

Once a desync is confirmed, common exploitation paths are:

Capturing other users' requests: smuggle a request prefix that forwards the victim's
subsequent request to an endpoint you control.

Bypassing access controls: prepend a prefix that sets a trusted header (`X-Forwarded-For:
127.0.0.1`, `X-Internal: true`) that the back-end uses to bypass access restrictions.

Delivering reflected XSS via a smuggled response: smuggle a request that causes the server
to respond with a reflected XSS payload to the victim's browser.

All attack development should be performed carefully against non-production or with prior
coordination to avoid affecting other users during testing.

## Output

- Confirmed desync type (CL.TE, TE.CL, H2.CL, H2.TE, client-side).
- Infrastructure details: reverse proxy and back-end technology identified.
- Demonstrated impact: access control bypass, request capture method, or XSS delivery.

## Techniques

- [HTTP request smuggling](../techniques/smuggling.md)
