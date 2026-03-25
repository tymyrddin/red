# Runbook: Web application surface discovery

Surface discovery builds the map before any active testing begins. The goal is to understand
what the application does, what it exposes, how it authenticates, and what technologies it runs
on. An engagement that skips this phase consistently misses endpoints and attack surface that
passive and low-noise discovery would have found for free.

## Prerequisites

- Target URL and scope definition.
- Burp Suite Pro with the proxy configured.
- LinkFinder, Feroxbuster, httpx, Wappalyzer (browser extension or CLI).
- A test account at each available privilege level.

## Phase 1: Passive discovery

Start without sending any requests to the target. Spend time here — it consistently yields
findings that active enumeration misses.

### Source repositories

Search GitHub, GitLab, and Bitbucket for the organisation name and primary domain. Look for:
- Committed API keys, tokens, and credentials.
- Deployment configuration files (`.env`, `docker-compose.yml`, Terraform files).
- Internal endpoint paths and schema files.
- Historical commit diffs that removed sensitive data (still visible in history).

### JavaScript bundles

JavaScript served to the browser frequently contains route definitions, API endpoint paths,
internal hostnames, and access token patterns. Extract them before browsing:

```bash
# Download the main JS bundle and extract URLs
curl -s https://target.com | grep -oP 'src="[^"]+\.js"' | \
  sed 's/src="//;s/"//' | xargs -I{} curl -s https://target.com{} > bundle.js

# Run LinkFinder against the bundle
python3 linkfinder.py -i bundle.js -o cli
```

### Wayback Machine

Historical snapshots surface deprecated endpoints and old API versions that may still be live:

```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" \
  | grep -E '\.(json|yaml|yml|xml|php|asp|aspx|jsp)$'
```

### Shodan and Censys

Index entries for the target surface exposed services, banners, and certificates:

```
hostname:target.com port:443
org:"Target Organisation" has_screenshot:true
```

## Phase 2: Technology fingerprinting

Before active testing, identify the stack. Security controls, injection sinks, and session
mechanisms vary significantly by framework.

Browse the login page and a few application pages through Burp with Wappalyzer active.
Note from the response headers and cookies:

- Server and framework headers (`X-Powered-By`, `Server`, `Via`).
- Session cookie names: `PHPSESSID` (PHP), `JSESSIONID` (Java), `ASP.NET_SessionId` (.NET).
- Error page formats: stack traces, ORM exceptions, and template errors reveal versions.
- Content-Security-Policy header: reveals what the application permits loaded, and gaps.

Check for common paths that expose version or configuration information without authentication:

```bash
for path in /server-info /server-status /phpinfo.php /.git/HEAD /WEB-INF/web.xml \
  /actuator /actuator/env /actuator/beans /_profiler /debug/default/view; do
  curl -s -o /dev/null -w "$path: %{http_code}\n" https://target.com$path
done
```

## Phase 3: Endpoint and parameter discovery

### Manual walkthrough

Route all traffic through Burp Suite. Use the application as every available account role,
exercising every feature available to that role. Let the proxy build a complete site map.
Pay particular attention to:

- Functionality that modifies data, not just reads it.
- Endpoints that accept file uploads, XML, or structured data.
- Background requests triggered by user actions (XHR and fetch calls visible in the proxy).

### Directory and endpoint brute-force

```bash
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -x php,asp,aspx,jsp,json,xml -k --status-codes 200,301,302,401,403 -t 50
```

### API schema discovery

Check common schema paths unauthenticated:

```bash
for path in /api/swagger.json /api/openapi.json /api/v1/swagger.json \
  /swagger/v1/swagger.json /openapi.json /api-docs /graphql; do
  curl -s -o /dev/null -w "$path: %{http_code}\n" https://target.com$path
done
```

If a schema is found, import it into Burp or Postman immediately. Review for: endpoints with
no authentication requirement in the spec, operations accepting `additionalProperties`, and
internal or administrative operations not exposed in the UI.

### Parameter discovery

For every endpoint identified, run Arjun to find undocumented parameters:

```bash
arjun -u https://target.com/api/v1/users -m GET
arjun -u https://target.com/profile/update -m POST
```

## Phase 4: Authentication model mapping

Before testing any authorisation or logic, document exactly how authentication works:

- What token format is in use (JWT, opaque session token, API key)?
- Where is the token stored (cookie, Authorization header, body parameter)?
- What happens when the token is absent, expired, or malformed?
- Are there multiple authentication endpoints, or different mechanisms per area of the app?

If the application uses JWT, decode every token received and note the algorithm, claims,
and expiry time. If the algorithm is `RS256` or `ES256`, attempt to obtain the public key
from the JWKS endpoint:

```bash
curl https://target.com/.well-known/jwks.json
```

## Output

By the end of surface discovery, you should have: a complete endpoint inventory in Burp's
site map, the technology stack and version where identifiable, the authentication mechanism
and token format, any credentials or API keys found in passive sources, and a prioritised
list of targets for active testing.

## Techniques

- [Authentication vulnerabilities](../techniques/auth.md)
- [Broken access control](../techniques/acl.md)
- [Information disclosure](../techniques/id.md)
