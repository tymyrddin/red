# HTTP Host header attacks

HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behaviour.

## Steps

Intercept the Request in Burp, and modify the Host header to an arbitrary value. When the site being tested is configured as the web server's default or fallback option, the page will display when given an improper Host header. When multiple websites are being hosted by the same web server or front-end, the response is an error.

* Check for flawed validation
* Send ambiguous requests to bypass front-end systems
* Inject Host Override headers
* Brute-Force Virtual Hosts

## Flawed validation

Instead of returning an `Invalid Host Header` response, the request may be blocked as a security measure. The server may still be vulnerable. Try some bypasses:

* Insert the payload within the port field. The domain name may be checked, but the port number may not be.
* Provide an arbitrary domain name containing the whitelisted domain name. Validation may simply check if the target domain is present in the response. 

## Ambiguous requests to bypass front-end systems

If a load balancer or CDN is in place acting as the front-end server, it may be possible to bypass security checks using one request, and have the application process the request on the back-end differently. 

* Insert duplicate Host headers
* Try an absolute URL
* Add line wrapping with space character

## Inject Host Override headers

If it is not possible to override the Host Header using one of the techniques mentioned above, try injecting the payload into a header that will override it:

    X-Host
    X-Forwarded-Server
    X-HTTP-Host-Override
    Forwarded

## Brute-Forcing virtual hosts

If publicly accessible websites and private, internal sites are hosted on the same server, the internal hostname may resolve to a private IP address.

* Guess the hostnames. 
* Try to discover a possibly hidden domain name through other means.
* Use Burp Intruder to brute-force virtual hosts using a simple wordlist of candidate subdomains.

## Escalation

* If the Host header value is used to build a URL for password reset links. If so, password reset poisoning attacks are possible. Password reset functionality abuse is the most common use of Host header attacks.
* If the application uses the Host header to build script URLs, attackers can use malicious Host headers for [web cache poisoning](cache.md). This can affect any vulnerable caching mechanisms between the client and the server, including a caching proxy run by the site itself, downstream providers, content delivery networks (CDNs), and syndicators. Once poisoned, the cache then serves malicious content to anyone who requests it, allowing for very effective persistent [cross-site scripting (XSS)](xss.md) attacks.
* If the application uses Host header values to construct SQL queries, it may be vulnerable to [SQL injection](sqli.md) via the Host header. 
* If it uses Host header values to construct operating system commands, it may be vulnerable to [OS command injection](rce.md). 
* The same applies to other types of server-side vulnerabilities caused by the application accepting user input from the Host header without validation.
* If the web server hosts other internal applications, Host header manipulation may allow attackers to access systems and functionality only accessible from the intranet or to local users, such as administrative panels. If local user authentication is based on the hostname, this opens up yet another attack vector.
* Manipulated Host headers can also open the way for attacks such as [server-side request forgery (SSRF)](ssrf.md). A typical scenario involves load-balancing system misconfigurations where the Host header is used to direct traffic to other sites on a local network. Header manipulation can then allow for specifying sites that should not be accessible from the outside.

## Portswigger lab writeups

* [Basic password reset poisoning](../burp/headers/1.md)
* [Host header authentication bypass](../burp/headers/2.md)
* [Web cache poisoning via ambiguous requests](../burp/headers/3.md)
* [Routing-based SSRF](../burp/headers/4.md)
* [SSRF via flawed request parsing](../burp/headers/5.md)
* [Host validation bypass via connection state attack](../burp/headers/6.md)
* [Password reset poisoning via dangling markup](../burp/headers/7.md)

## Remediation

* Protect absolute URLs. Specify the current domain in a configuration file and refer to this value instead of the Host header. Use `$_SERVER['SERVER_NAME']` and enforce it at the httpd (Apache, nginx, etc.) configuration level. Have an explicitly configured virtual host for each domain served. Do not allow "catch-all" configurations.
* When using a web application framework, use the hostname value stored by the framework. Frameworks ask for the hostname during setup and store that value securely in a configuration file.
* If your application needs the value of the Host header and there is no workaround, check it against a whitelist of permitted domains and reject or redirect any requests for unrecognised hosts. 

```text
$domains = ['this.example.com', 'that.example2.org'];
if ( ! in_array($_SERVER['SERVER_NAME'], $domains)) {
    // error
}
```

* To prevent routing-based attacks on internal infrastructure, configure load balancers or any reverse proxies to forward requests only to a whitelist of permitted domains.
* Don't support Host override headers, in particular X-Forwarded-Host.
* Avoid hosting internal-only websites and applications on the same server as public-facing content.

## Resources

* [Portswigger: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
* [OWASP: Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
