# Runbook: Web cache poisoning

Web cache poisoning is a delivery mechanism, not a payload. The aim is to get a harmful
response stored in a shared cache so that ordinary users are served it in place of the
legitimate page. Its severity tracks whatever is being delivered, often reflected XSS turned
persistent. The method comes down to finding an input the cache ignores but the application
reflects, then getting the poisoned response to stick.

## Prerequisites

- A target sitting behind a cache (a CDN, reverse proxy, or the application's own cache).
- Burp Suite with the Param Miner extension for discovering unkeyed inputs and adding cache
  busters.
- A reflected-input or DOM sink already identified, since poisoning needs something worth
  caching.

## Phase 1: Read the cache

Establish how the cache behaves before trying to poison it. Send a request twice and watch
the response headers:

```
X-Cache: miss        # then on the repeat:
X-Cache: hit
Age: 0               # rising on subsequent requests
```

`X-Cache`, `Age`, `CF-Cache-Status`, and `Cache-Control` indicate whether a response was
served from cache and roughly how long it lives. Identify which URLs are cached at all; an
uncached endpoint cannot be poisoned.

## Phase 2: Find unkeyed inputs

The cache key is the set of request components the cache uses to decide whether two requests
are equivalent. An input that is reflected in the response but left out of the key is the
opening. Add a cache buster to a unique query parameter so probing does not poison the real
cache entry, then use Param Miner to fuzz headers:

```
GET /?cb=12345 HTTP/1.1
X-Forwarded-Host: example.com
X-Forwarded-Scheme: nothttps
X-Host: example.com
```

Watch for a header value appearing in the response. A reflected value that is not part of the
key is the candidate. Cookies, the request method, and the port can all be unkeyed too.

## Phase 3: Build the payload

Work out how the reflected input reaches the response and craft accordingly:

- A header reflected into a script source or link allows an attacker host to be swapped in.
- A header reflected into HTML carries an XSS payload directly.
- An unkeyed query string reflected into the page turns reflected XSS into stored XSS held in
  the cache.

Where a single header is too constrained, combine several (one to set the host, another to
force HTTPS) to reach an exploitable sink.

## Phase 4: Fat GET and parameter cloaking

Where the cache keys the query string but the application also reads the request body, a GET
request carrying a body (a fat GET) can smuggle an unkeyed parameter:

```
GET /?param=safe HTTP/1.1
Content-Length: 14

param=payload
```

Parameter cloaking hides a second copy of a parameter the cache does not parse the same way
the application does, for example by exploiting differing delimiter handling
(`?cb=1&utm_content=x;param=payload`).

## Phase 5: Land and confirm

Remove the cache buster and send the malicious request so the response is stored against the
real cache key. Then request the page as a normal user would, with a clean request, and
confirm the poisoned response comes back from cache. Note the cache lifetime so the
demonstrated blast radius is honest.

## Output

- The unkeyed input (header, cookie, query, method, port) and the sink it reaches.
- The cached payload and proof that a clean request is served the poisoned response.
- Cache lifetime and the population of users in range.

## Techniques

- [Web cache poisoning](../techniques/cache.md)
- [HTTP Host header attacks](host-header.md)

## Counter moves

Runbook: Web cache poisoning is what this page works through. Keying every input that affects
the response, stripping unkeyed headers, and refusing fat GET requests are the counters. The
defender's view is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
