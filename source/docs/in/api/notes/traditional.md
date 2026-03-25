# Injection via APIs

APIs pass user input to the same backend systems as web applications: relational and NoSQL
databases, operating system shells, template engines, XML parsers, and internal HTTP clients.
The injection vulnerability classes are the same; the delivery mechanism differs.

## SQL injection

SQL injection in APIs typically arrives in JSON request bodies or query string parameters rather
than HTML form fields. The payload and exploitation are identical to web application SQL injection;
the context changes what the payload looks like on the wire.

APIs are often less well-tested for injection than their web frontends because they are developed
separately and tested with functional rather than security-focused tests. An API endpoint that was
written quickly for a mobile client and never reviewed is a common location for SQL injection that
the web frontend does not have.

## NoSQL injection

Document stores and key-value databases have their own injection classes. MongoDB query operator
injection (`$ne`, `$gt`, `$where`) is the most common. When user input is passed directly into a
MongoDB query document without type enforcement, operators in the input are interpreted.

The impact of NoSQL injection varies by operator: `$ne: null` on a login query returns all users,
`$where` with a JavaScript expression can exfiltrate data character by character.

## SSRF

Server-side request forgery through APIs is particularly valuable because cloud-hosted APIs run
on infrastructure where the instance metadata service is reachable at a predictable internal
address. An API that fetches a URL supplied by the caller can be redirected to retrieve AWS,
Azure, or GCP instance credentials, internal service endpoints, or resources behind the network
perimeter.

SSRF is most commonly found in APIs that offer webhook registration, image loading from URL,
document import from URL, or any functionality described as "fetch from" or "import from".

## Command injection

APIs that wrap command-line tools (image processing, file conversion, archive handling, network
utilities) sometimes pass user-supplied input to shell commands without sufficient escaping.
Time-based detection (injecting `sleep 5` and observing the response delay) confirms injection
when output is not reflected.

## XML external entity (XXE)

SOAP services and REST APIs that accept XML are vulnerable to XXE when the parser processes
external entity declarations. XXE can read arbitrary files from the server, perform server-side
request forgery, or in some configurations achieve remote code execution.

SOAP services deserve specific attention because they are XML-based by design and are often older,
less frequently reviewed, and assumed to be internal-only (and therefore not subject to the same
security controls as public APIs).

## Template injection

Template engines used to generate API responses are vulnerable when user-controlled strings are
rendered inside templates without escaping. The specific payload depends on the engine; detection
uses mathematical expressions that different engines evaluate differently.

## Runbooks

- [Injection testing](../runbooks/injection.md)
