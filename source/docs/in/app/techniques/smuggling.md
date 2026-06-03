# HTTP Request smuggling

HTTP request smuggling vulnerabilities occur when the frontend and the backend interpret the boundary of an HTTP request
differently causing de-synchronisation between them. This is due to numerous frontend and backend libraries deviating
from RFC specifications when dealing with both the `Content-Length` and the `Transfer-Encoding` header. HTTP request
bodies can be framed according to these two headers and deviations from the specification occur. As a result, part of a
request gets appended or smuggled, to the next one which allows the response of the smuggled request to be provided to
another user.

* The body can vary from application to application, framework to framework, and the `Content-Length` and
  `Transfer-Encoding: chunked` headers are applicable to `HTTP/1.1` and partially to `HTTP/1.0`, but not to
  `HTTP/2`. That written, other forms of smuggling are possible with the latter.
* HTTP 1.1 allows for sending both `Content-Length` (`CL`) and `Transfer-Encoding` (`TE`) headers in the same request,
  but when both are sent, `TE` takes precedence.
* A parent smuggled request carries both headers, to trick the servers.
* A child smuggled request is the ideal request hidden inside the parent, ideal because it carries only one of the
  headers.

## Steps

Send malformed requests to check for:

* `CL:CL`: When provided with two `Content-Length` headers, if implementation differences occur between a frontend and a
  backend on which `Content-Length` header is prioritised, smuggling attacks can occur.
* `CL:TE`: Different HTTP libraries tolerate different variations of the `Transfer-Encoding` header and will normalise
  them to improve client experience. By understanding what variations of the `TE` header is normalised by the backend
  server, it might be possible to smuggle a malformed `TE` header through the frontend and conduct a `CL:TE` smuggling
  attack. The first part of a request declares a short chunk length, typically `0`. The frontend server reads only the
  first part of the request and passes the second part to the back-end server.
* `TE:TE`: Frontend and backend servers correctly prioritise the Transfer-Encoding header, but the header can be
  obfuscated to trick one of the servers.
* `TE:CL` : The frontend server prioritises the `Transfer-Encoding` weakness, while the backend server prioritises the
  `Content-Length` weakness, making it possible to declare the length of the first chunk up to and including the
  malicious request. The second chunk is declared as having `0` length, so the frontend server assumes the request is
  complete. It passes the request to the backend server, which receives and processes it.

## Escalation

* Gain access to protected resources, such as admin consoles
* Gain access to sensitive data
* Hijack sessions of web users
* Launch [cross-site scripting (XSS) attacks](xss.md) without requiring any action from the user
* Credential hijacking

## Variants

The classic forms are CL.TE and TE.CL, detected by timing and confirmed by differential
responses, with TE-header obfuscation to slip past one server. Exploitation runs to bypassing
front-end controls, revealing front-end request rewriting, capturing other users' requests,
and delivering reflected XSS. The HTTP/2 family adds H2.TE and H2.CL, CRLF-based smuggling and
splitting, request tunnelling, and response queue poisoning; CL.0 and server-side pause-based
smuggling extend it further; and client-side desync needs no privileged network position.
Several of these land in a cache, as poisoning or deception. The
[request smuggling and desync runbook](../runbooks/desync.md) works through detection,
confirmation, and attack development.

## Resources

* [Portswigger: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
* [Snyk: Demystifying HTTP request smuggling](https://snyk.io/blog/demystifying-http-request-smuggling/)
* [OWASP: Testing for HTTP Splitting Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling)

## Counter moves

HTTP Request smuggling is the variant in play. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defensive counterpart is in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
