# Same-origin policy (SOP)

Websites often loosen the same-origin policy (SOP) to have more flexibility. These controlled and intended SOP bypasses can have adverse effects, as attackers can sometimes exploit misconfigurations in these techniques. These exploits can cause private information leaks and lead to more vulnerabilities, such as authentication bypass, account takeover, and large data breaches.

## Steps

1. Find out if the application uses any SOP relaxation techniques. Is the application using CORS, postMessage, or JSONP?
2. If the site is using CORS, test the strength of the CORS allowlist by submitting test `Origin` headers.
3. If the site is using postMessage, see if you can send or receive messages as an untrusted site.
4. If the site is using JSONP, try to embed a script tag on your site and request the sensitive data wrapped in the JSONP payload.
5. Determine the sensitivity of the information you can steal using the vulnerability, and see if you can do something more.
6. Create report.

## Determine if SOP relaxation techniques are used

You can determine whether the target is using an SOP-relaxation technique by looking for the signatures of each SOP-relaxation technique. When you’re browsing a web application, open your proxy and look for any signs of cross-origin communication. For example, CORS sites will often return HTTP responses that contain an `Access-Control-Allow-Origin` header. 

A site could be using postMessage() if you inspect a page (for example, by right-clicking it in Chrome and choosing Inspect, then navigating to Event Listeners) and find a message event listener.

And a site could be using `JSONP` if you see a URL being loaded in a `script` tag with a `callback` function.

## Find CORS misconfiguration

If the site is using CORS:

* Check whether the `Access-Control-Allow-Origin` response header is set to `null`. 
* If not, send a request to the site with the origin header `attacker.com`, and see if the `Access-Control-Allow-Origin` in the response is set to `attacker.com`.
* Test whether the site properly validates the origin URL by submitting an Origin header that contains an allowed site, such as `www.example.com.attacker.com`. Check the `Access-Control-Allow-Origin` header returns the origin of the attacker's domain.
* If one of these `Access-Control-Allow-Origin` header values is returned, you have found a CORS misconfiguration. Attackers will be able to bypass the SOP and exfiltrate data.

## Find postMessage bugs

If the site is using postMessage:

* See if you can send or receive messages as an untrusted site. Create an HTML page with an iframe that frames the targeted page accepting messages. Try to send messages to that page that trigger a state-changing behaviour. 
* If the target cannot be framed, open it as a new window instead.
* You can also create an HTML page that listens for events coming from the target page, and trigger the postMessage from the target site. See if you can receive sensitive data from the target page.

## Find JSONP issues

If the site is using `JSONP`, see if you can embed a script tag and request the sensitive data wrapped in the JSONP payload.

## Consider mitigating factors

When the target site does not rely on cookies for authentication, these SOP bypass misconfigurations might not be exploitable. For instance, when the site uses custom headers or secret request parameters to authenticate requests, you might need to find a way to forge those to exfiltrate sensitive data.

## Escalation

An SOP-bypass bug often means that attackers can read private information or execute action as other users. This means that these vulnerabilities are often of high severity before any escalation attempts. But you can still escalate SOP-bypass issues by automation or by pivoting the attack using the information found. 

Many researchers will simply report CORS misconfigurations without showing the impact of the vulnerability. Consider the impact of the issue before sending the report.

## Portswigger lab writeups

* [CORS vulnerability with basic origin reflection](../burp/cors/1.md)
* [CORS vulnerability with trusted null origin](../burp/cors/2.md)
* [CORS vulnerability with trusted insecure protocols](../burp/cors/3.md)
* [CORS vulnerability with internal network pivot attack](../burp/cors/4.md)

## Remediation

* Origins specified in the `Access-Control-Allow-Origin` header should only be sites that are trusted. 
* Dynamically reflecting origins from cross-origin requests without validation is exploitable and to be avoided.
* Also avoid using the header `Access-Control-Allow-Origin: null`. Cross-origin resource calls from internal documents and sandboxed requests can specify the `null` origin. CORS headers must be  defined in respect of trusted origins for private and public servers. 
* Avoid using wildcards in internal networks. Trusting network configuration alone to protect internal resources is not sufficient when internal browsers can access untrusted external domains. 
* CORS defines browser behaviours and is not a replacement for server-side protection of sensitive data - an attacker can directly forge a request from any trusted origin. Web servers should apply protections for sensitive data, such as authentication and session management, in addition to properly configured CORS. 

## Resources

* [Portswigger: Same-origin policy (SOP)](https://portswigger.net/web-security/cors/same-origin-policy)
* [OWASP: Cross Site History Manipulation (XSHM)](https://owasp.org/www-community/attacks/Cross_Site_History_Manipulation_(XSHM))
* [Exploiting CORS misconfigurations for Bitcoins and bounties, James Kettle](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [StackStorm - From Originull to RCE - CVE-2019-9580](https://quitten.github.io/StackStorm/)
* [HackTricks: CORS - Misconfigurations & Bypass](https://book.hacktricks.xyz/pentesting-web/cors-bypass)
* [HackTricks: postMessage Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities)
* [Think Outside the Scope: Advanced CORS Exploitation Techniques](https://infosecwriteups.com/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
* [PayLoadsAllTheThings: CORS miscinfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md)
