# Runbook: Endpoint discovery

Endpoint discovery builds the complete map of what the API exposes before any testing begins. The
documented endpoints are the starting point, not the destination. The goal is to find everything,
including what is not in the documentation.

## Objective

Produce a complete list of API endpoints, their HTTP methods, and any parameters they accept.
Identify endpoints that are reachable but undocumented, deprecated, or in environments not intended
for external access.

## Prerequisites

- Target domain and any known API base URLs.
- Burp Suite Pro or ZAP configured as a proxy.
- Postman for collection building and request replay.
- Kiterunner for route brute-forcing.
- SecLists API wordlists.
- Access to the application as a registered user, where scope permits.

## Phase 1: Collect from passive sources

Before sending any requests to the API, gather endpoint information from sources that do not
require active interaction.

### JavaScript bundle analysis

Fetch the application and extract all JavaScript sources:

```bash
# Download the main page and extract script URLs
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"'

# Download each bundle and extract path-like strings
curl -s https://target.com/static/main.abc123.js | \
  grep -oP '"(/api/[a-z0-9/_{}.-]+)"' | sort -u
```

LinkFinder handles this more thoroughly, following script imports and deobfuscating where possible:

```bash
python3 linkfinder.py -i https://target.com -d -o results.html
```

### Wayback Machine

Retrieve all URLs ever crawled for the target domain:

```bash
waybackurls target.com | sort -u > wayback.txt
grep -E "(/api/|/v[0-9]/|/graphql|/rest/)" wayback.txt
```

Pay attention to paths that no longer appear in the current application. Old endpoints that were
removed from the frontend may still respond on the backend.

### Documentation paths

Check all common documentation endpoint paths with a single request each:

```bash
for path in /api-docs /swagger.json /swagger.yaml /openapi.json /openapi.yaml \
            /v1/api-docs /v2/api-docs /api/swagger /docs /redoc \
            /api/v1/swagger.json /api/v2/swagger.json /.well-known/; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
  [ "$status" != "404" ] && echo "$status $path"
done
```

A `200` or `301` on any of these paths means documentation is available. Import it into Postman
immediately for structured testing.

## Phase 2: Proxy-based discovery

Route all application traffic through Burp Suite and use every feature of the application
systematically. The proxy builds a map of every API call the frontend makes.

Use the application as intended: log in, navigate every page, submit every form, trigger every
state change. Check every user role available in the scope. Admin accounts call endpoints that
regular user accounts do not. Enumerating all roles produces a more complete map.

After completing the manual walkthrough, review the Burp Suite site map. Filter to the target
domain and sort by endpoint path. Look for:

- Endpoints that appear only once (may be rare code paths worth investigating)
- Endpoints with unusual parameter names or structures
- Endpoints that return different status codes for different inputs
- Versioned paths that suggest older API versions are still active

Export the discovered endpoints as a Postman collection for systematic follow-up.

## Phase 3: Active route brute-forcing

Supplement the proxy-discovered endpoints with active wordlist-based discovery.

Kiterunner uses API-specific wordlists and understands API route structures, making it more
effective than generic directory brute-forcing:

```bash
# Download the routes wordlist
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz

# Run against the target
kr scan https://target.com/api -w routes-large.kite -x 20 --ignore-length 34
```

The `--ignore-length` flag filters out responses of a specific body length that indicates a
generic 404 page, which varies by application.

For REST APIs with a known base path, supplement with a targeted wordlist:

```bash
gobuster dir \
  -u https://target.com/api/v1 \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
  -x json \
  -b 404,302
```

For versioned APIs, check all plausible version numbers:

```bash
for version in v1 v2 v3 v4 v5 2 3 2.0 2.1; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/${version}/users")
  [ "$status" != "404" ] && echo "LIVE: /api/${version}/users → $status"
done
```

## Phase 4: Parameter discovery

For each discovered endpoint, find all the parameters it accepts. Endpoints frequently accept
parameters not listed in the documentation.

Use Arjun to automate parameter discovery:

```bash
arjun -u https://target.com/api/v1/users -m GET
arjun -u https://target.com/api/v1/users -m POST
```

Manually review responses for fields that suggest additional parameters: an object in the response
that is not in the request often means the field can be set in a subsequent request. A `filter`
field in a list response suggests a `filter` query parameter on the GET endpoint.

Check how the API handles unknown parameters. Some APIs silently ignore them. Others reflect them
in the response. Others fail in ways that reveal internal structure.

## Phase 5: Build the Postman collection

Consolidate everything into a structured Postman collection for systematic testing.

For each endpoint, create a request with:
- Correct HTTP method
- All known parameters with example values
- The required authentication headers
- A description noting where the endpoint was discovered

Organise by resource type (users, orders, products) rather than by HTTP method. This makes it
easier to test a complete resource's access control systematically.

Use Postman environment variables for the base URL, authentication tokens, and any IDs that
appear across multiple requests. This makes the collection reusable across different environments
and test accounts.

## Output

- Complete endpoint list with HTTP method, path, and discovery source.
- Postman collection with all endpoints, parameters, and authentication configured.
- List of deprecated or version-discrepancy endpoints.
- Any documentation files retrieved (OpenAPI spec, WSDL, GraphQL schema).

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
- [GraphQL attack chain](../playbooks/graphql.md)
