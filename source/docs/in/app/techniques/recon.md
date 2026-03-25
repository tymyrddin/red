# Web application surface discovery

Web application surface is larger and less well-defined than it appears from the browser.
The documented interface is the starting point. What an attacker actually has to work with
includes every undocumented endpoint reachable from the network, every parameter not
surfaced in the UI, every API version left running after a newer one was deployed, and
every third-party integration the application depends on.

Understanding the surface before active testing determines which vulnerabilities get found
and which get missed entirely.

## The application is not just what the browser shows

Single-page applications load significant logic into the browser as JavaScript. That logic
contains route definitions, API endpoint paths, parameter names, and sometimes internal
hostnames and configuration values. None of this is documented; all of it is readable. A
tester who only observes what the browser renders has already missed a significant portion
of the attack surface.

Mobile clients, desktop applications, and integrations with third-party services call the
same API as the browser but often expose different endpoints or use different authentication
flows. The API surface tested from a web browser may be a subset of the total surface.

## Passive sources

Source repositories are the most valuable passive source. Developers commit configuration
files, deployment scripts, and occasionally credentials. Even after a sensitive value is
removed, it remains visible in the commit history. A repository containing an `.env.example`
with credential field names, or a Terraform file describing the infrastructure, reveals
the architecture without any active interaction.

JavaScript bundles downloaded from the application contain routes, parameter names, and
API paths extracted with LinkFinder or similar tools. These paths frequently include
administrative endpoints, debug routes, and API versions that are not linked anywhere in
the UI but remain accessible.

Wayback Machine archives preserve endpoint paths from previous versions of the application.
A deprecated API version that was removed from the documentation in 2022 may still respond
in 2026 if the team removed the link but not the code.

## Technology identification

The framework and language in use determines the attack surface beyond the specific
application's endpoints. A Rails application exposes different default paths than a Spring
Boot application. A Django application with debug mode accidentally enabled exposes the full
URL routing table. An Express application using a misconfigured static file handler may
serve source files.

Response headers, cookie names, and error page formats identify the stack. The `Server`
header, `X-Powered-By`, the session cookie name (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`),
and the format of error messages are all fingerprints. Stack traces and ORM error messages
identify specific versions and sometimes the database schema.

## The continuous surface

Modern applications add endpoints continuously. CI/CD pipelines deploy changes multiple
times per day. A new microservice, a new API version, a new internal tool behind an
authenticated endpoint: these all expand the surface faster than any point-in-time
assessment can track.

Organisations that run continuous testing programmes use automated crawling and endpoint
diffing to identify new surface as it appears, rather than discovering it during an annual
assessment. For an assessment, this means the surface mapped on day one may not be complete
by the time testing begins.

## Runbooks

- [Web application surface discovery](../runbooks/recon.md)
