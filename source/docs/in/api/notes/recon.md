# API surface discovery

APIs are almost always larger than their documentation suggests. The documented surface is what the
developer intended to expose. The actual surface includes staging endpoints, versioned paths that were
never retired, internal endpoints reachable from the internet, and third-party integrations the
organisation has forgotten about. Finding all of it before touching anything is where API testing starts.

## What you are looking for

The goal is a complete inventory of endpoints, the authentication model, the data types the API handles,
and any credentials or schema material exposed in public sources. Active testing against an undocumented
surface produces better results than active testing against a documented one, because undocumented
endpoints tend to have weaker controls and less monitoring.

## Passive sources

### JavaScript bundles

Modern web applications build their frontend from JavaScript that is served to the browser. That
JavaScript contains the API endpoint paths the application calls. It is delivered publicly, without
authentication, to every visitor.

Fetch the application's main page and extract all script sources. Download each script and search
for API paths:

```bash
# extract script URLs from a page
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//' | sed 's/"//'

# search a downloaded bundle for API paths
grep -oP '(?<=")[/][a-z0-9/_-]{3,}(?=")' bundle.js | sort -u
```

LinkFinder automates this across all script files found on a page:

```bash
python3 linkfinder.py -i https://target.com -d -o cli
```

### Source code repositories

Search GitHub, GitLab, and Bitbucket for repositories belonging to the organisation. API endpoints,
base URLs, parameter names, and sometimes credentials appear in source code, configuration files,
test suites, and commit history.

Search specifically for:
- API base URL constants
- Route definitions in the framework used (Express routes, Django URL patterns, Spring mappings)
- OpenAPI or Swagger specification files committed alongside the code
- `.env` files committed accidentally
- Test files that call API endpoints with example payloads

TruffleHog finds secrets; manual review finds endpoints and structure.

### Documentation and specification files

Many APIs expose their specification at predictable paths even when not linked from the main
application. Check before running any active enumeration:

```
/api-docs
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/v1/api-docs
/v2/api-docs
/api/swagger
/docs
/redoc
/.well-known/
```

For GraphQL APIs, introspection is often enabled by default and reveals the complete schema. Check
the common GraphQL endpoint paths:

```
/graphql
/api/graphql
/v1/graphql
/query
/gql
```

For SOAP services, the WSDL is typically at the service endpoint with `?wsdl` appended.

### Historical sources

The Wayback Machine archives versions of the application including API documentation, legacy
endpoints, and configuration pages that have since been removed. Waybackurls retrieves the full
URL history efficiently:

```bash
waybackurls target.com | grep -E "(api|v[0-9]|endpoint|graphql)" | sort -u
```

Old API versions that no longer appear in documentation are often still live. A `/v1/` endpoint
may have been superseded by `/v2/` in the documentation while remaining fully functional and
without the security controls added in the newer version.

### Shodan and Censys

Search for API management interfaces, documentation portals, and backend services exposed on
non-standard ports:

```
hostname:target.com port:8080
hostname:target.com port:3000
ssl:"target.com" "swagger"
ssl:"target.com" "graphql"
```

Development and staging environments are frequently indexed by Shodan and frequently have weaker
controls than production.

## Framework and technology identification

Identifying the API framework changes what to look for in active testing. Framework-specific
paths, error formats, and default behaviours are consistent enough to be useful.

HTTP response headers reveal framework details without any active probing. The `Server`,
`X-Powered-By`, `X-Generator`, and framework-specific headers (`X-AspNet-Version`,
`X-Django-Version`) identify the stack. Error responses, when triggered, often include stack
traces or framework-specific error formats.

Common REST frameworks have characteristic endpoint patterns. Spring Boot applications expose
`/actuator/` endpoints for monitoring that are sometimes accessible unauthenticated. Express
applications often return distinctive error JSON. Django REST Framework returns a browsable API
on HTML requests to API endpoints.

GraphQL APIs are identifiable by the `Content-Type: application/json` response to a POST with
a `query` field, and by the specific error format when malformed queries are submitted.

## Authentication model

Determine how authentication works before testing anything that requires credentials.

Where does the token appear: Authorization header (Bearer or Basic), a custom header, a query
parameter, or a cookie? The location affects how tokens are captured and whether they are
included in CORS preflight requests.

What type of token: JWT, opaque session token, API key, OAuth access token, or certificate?
JWT tokens are base64-decodable and reveal the algorithm, claims, and sometimes exploitable
misconfigurations without any active testing.

Is the token the same for all requests or does it change per session? Short-lived tokens with
refresh mechanisms behave differently under testing than long-lived API keys.

## What to produce

By the end of passive API recon, you should have: a list of known endpoints from documentation,
JavaScript bundles, and historical sources; the framework and technology stack; the authentication
model; any credentials or tokens found in public repositories; and a shortlist of endpoints worth
prioritising for active testing.

## Runbooks

- [Endpoint discovery](../runbooks/endpoint-discovery.md)
- [Schema analysis](../runbooks/schema-analysis.md)
- [Authentication testing](../runbooks/auth-testing.md)
- [BOLA and BFLA testing](../runbooks/bola-bfla.md)
