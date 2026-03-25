# Playbook: Web application attack chain

This playbook connects the web application runbooks into an operational sequence. It covers
the full chain from passive surface discovery through to documented findings, with decision
points that determine which vulnerabilities to pursue and in what order.

## Objective

Identify exploitable vulnerabilities across the full web application stack: authentication
weaknesses, access control failures, server-side injection, client-side execution, workflow
abuse, and protocol-level attacks. Produce findings expressed as concrete impact rather than
theoretical risk.

## Prerequisites

- Target URL, scope definition, and rules of engagement.
- Burp Suite Pro with DOM Invader, Autorize, Turbo Intruder, and HTTP Request Smuggler.
- At least two test accounts at different privilege levels, ideally three (unauth, user,
  admin).
- An OOB detection channel (Burp Collaborator).

## Passive discovery

Start without sending any requests to the application. Spend at least an hour here.

Search source repositories (GitHub, GitLab) for the organisation name and domain. Any
committed credentials are the first finding and the highest priority. Record API keys,
tokens, and internal paths found in public repositories.

Extract endpoint paths from JavaScript bundles served by the application. Archive Wayback
Machine URLs for the primary domain, filtering for structured data formats and endpoint
paths.

Fingerprint the technology stack from DNS records, certificate transparency logs, and any
documentation or job postings that describe the architecture.

If any credentials or tokens are found passively, validate them immediately before
proceeding. A valid token from a passive source is the engagement's best possible opening.

## Surface mapping

Route all traffic through Burp Suite. Use the application as every available account role,
exercising every feature. Let the proxy build a complete site map.

Run Feroxbuster against the application root to find undocumented directories and endpoints:

```bash
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -x php,asp,aspx,jsp,json -k -t 50
```

Check for API schema files at common paths unauthenticated. If an OpenAPI or GraphQL schema
is found, import it and review it before any active testing. Look immediately for
unauthenticated endpoints, endpoints that accept arbitrary extra fields, and internal
operations.

## Authentication testing

Before testing anything else, confirm the authentication model and its weaknesses.

Remove authentication from every endpoint in the site map and replay. Any that return data
without authentication are immediate findings.

If the application uses JWT, run algorithm confusion tests with jwt_tool. If opaque session
tokens, analyse a sample of twenty for predictability. Test the password reset flow for
host-header injection, token fixation, and missing expiry. Test 2FA endpoints for rate
limiting and step-bypass.

The authentication surface determines the value of all subsequent findings. A session that
cannot be forged limits CSRF and XSS impact; one that can be predicted or bypassed multiplies
the impact of everything else.

## Access control

With two test accounts, systematically test IDOR across every resource type. Configure
Autorize with Account B's credentials and browse as Account A. Review every flagged response.

For every endpoint that returns `403` to the lower-privilege account, test HTTP method
override, path encoding variants, and direct parameter manipulation. Test mass assignment on
every update endpoint by adding `role`, `is_admin`, and `permissions` fields to the request
body.

Map every multi-step workflow and attempt to reach terminal states by skipping intermediate
steps. Any step that can be bypassed is frontend-only enforcement.

## Workflow and business logic testing

After the access control pass, shift from "is this endpoint secure?" to "what can someone
achieve using this application in sequences the developer did not test?"

For every workflow with a valuable terminal state, test:

- Whether concurrent requests to the check-and-write step produce multiple successes.
- Whether parameters set early in the flow are re-validated at the confirmation step.
- Whether the flow can be completed out of order or in reverse.

For any financial or quota-based feature, send twenty concurrent requests using Turbo
Intruder's single-packet attack. Document any that produce more successes than the limit
allows, and calculate the economic impact.

## Server-side injection

For every parameter that feeds a backend operation, test for injection.

Start with SSRF: any parameter that the server uses to make an outbound request. Use Burp
Collaborator as the target and look for OOB interactions. SSRF is frequently present in
image loaders, webhook endpoints, URL preview features, and document importers.

Test every parameter that appears in a data-access response for SQL injection. Use
time-based detection for parameters where boolean differences are not visible.

Test any endpoint that renders dynamic content from user input for SSTI. Inject `{{7*7}}`
and `${7*7}` and look for `49` in the response.

For any endpoint that processes XML (including SVG uploads and SOAP endpoints), test XXE
with an OOB payload to Collaborator.

## Client-side testing

Test every input field that produces output displayed to other users for stored XSS.
Use a payload that sends the session cookie to Collaborator and verify with a second account.

Test every parameter that appears in the response for reflected XSS. Use DOM Invader to
identify DOM sources that flow to dangerous sinks.

For every state-changing endpoint that does not contain a CSRF token, test whether a
cross-origin form submission succeeds.

Test request smuggling against every reverse-proxied endpoint using HTTP Request Smuggler.
Any confirmed desync should be developed into a demonstrable access control bypass or
request capture.

## Evidence collection

For each finding, capture:

- The exact request and response demonstrating the vulnerability.
- The account identities used (Token A = user X, Token B = user Y).
- The demonstrated impact: data accessed, state changed, privilege gained.
- For business logic findings, the economic or operational value of the outcome.
- A reproducible proof of concept: the exact steps another person could follow to
  replicate the finding.

## Runbooks

- [Surface discovery](../runbooks/recon.md)
- [Authentication testing](../runbooks/auth-testing.md)
- [Access control testing](../runbooks/access-control.md)
- [Workflow and business logic testing](../runbooks/business-logic.md)
- [Server-side injection](../runbooks/injection.md)
- [Client-side attacks](../runbooks/client-side.md)
- [HTTP request smuggling](../runbooks/desync.md)
