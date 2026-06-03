# HTTP Host header attacks

HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the
server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use
this input to inject harmful payloads that manipulate server-side behaviour.

## Steps

Intercept the Request in Burp, and modify the Host header to an arbitrary value. When the site being tested is
configured as the web server's default or fallback option, the page will display when given an improper Host header.
When multiple websites are being hosted by the same web server or front-end, the response is an error.

* Check for flawed validation
* Send ambiguous requests to bypass front-end systems
* Inject Host Override headers
* Brute-Force Virtual Hosts

## Flawed validation

Instead of returning an `Invalid Host Header` response, the request may be blocked as a security measure. The server may
still be vulnerable. Try some bypasses:

* Insert the payload within the port field. The domain name may be checked, but the port number may not be.
* Provide an arbitrary domain name containing the whitelisted domain name. Validation may simply check if the target
  domain is present in the response.

## Ambiguous requests to bypass front-end systems

If a load balancer or CDN is in place acting as the front-end server, it may be possible to bypass security checks using
one request, and have the application process the request on the back-end differently.

* Insert duplicate Host headers
* Try an absolute URL
* Add line wrapping with space character

## Inject Host Override headers

If it is not possible to override the Host Header using one of the techniques mentioned above, try injecting the payload
into a header that will override it:

```html
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
```

## Brute-Forcing virtual hosts

If publicly accessible websites and private, internal sites are hosted on the same server, the internal hostname may
resolve to a private IP address.

* Guess the hostnames.
* Try to discover a possibly hidden domain name through other means.
* Use Burp Intruder to brute-force virtual hosts using a simple wordlist of candidate subdomains.

## Escalation

* If the Host header value is used to build a URL for password reset links. If so, password reset poisoning attacks are
  possible. Password reset functionality abuse is the most common use of Host header attacks.
* If the application uses the Host header to build script URLs, attackers can use malicious Host headers
  for [web cache poisoning](cache.md). This can affect any vulnerable caching mechanisms between the client and the
  server, including a caching proxy run by the site itself, downstream providers, content delivery networks (CDNs), and
  syndicators. Once poisoned, the cache then serves malicious content to anyone who requests it, allowing for very
  effective persistent [cross-site scripting (XSS)](xss.md) attacks.
* If the application uses Host header values to construct SQL queries, it may be vulnerable to [SQL injection](sqli.md)
  via the Host header.
* If it uses Host header values to construct operating system commands, it may be vulnerable
  to [OS command injection](rce.md).
* The same applies to other types of server-side vulnerabilities caused by the application accepting user input from the
  Host header without validation.
* If the web server hosts other internal applications, Host header manipulation may allow attackers to access systems
  and functionality only accessible from the intranet or to local users, such as administrative panels. If local user
  authentication is based on the hostname, this opens up yet another attack vector.
* Manipulated Host headers can also open the way for attacks such as [server-side request forgery (SSRF)](ssrf.md). A
  typical scenario involves load-balancing system misconfigurations where the Host header is used to direct traffic to
  other sites on a local network. Header manipulation can then allow for specifying sites not meant to be accessible
  from the outside.

## Variants

The escalations from a trusted Host header are password-reset poisoning (including the
dangling-markup variant), authentication bypass where an internal-looking Host is granted
extra trust, web cache poisoning via ambiguous requests, and routing-based SSRF reached
through flawed request parsing or a connection-state attack. The
[Host header attacks runbook](../runbooks/host-header.md) works from probing the header
through to these escalations.

## Resources

* [Portswigger: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
* [OWASP: Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)

## Counter moves

HTTP Host header attacks is the case here. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defender's view can be found in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
