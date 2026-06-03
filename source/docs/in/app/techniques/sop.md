# Same-origin policy (SOP)

Websites often loosen the same-origin policy (SOP) to have more flexibility. These controlled and intended SOP bypasses
can have adverse effects, as attackers can sometimes exploit misconfigurations in these techniques. These exploits can
cause private information leaks and lead to more vulnerabilities, such as authentication bypass, account takeover, and
large data breaches.

## Steps

1. Find out if the application uses any SOP relaxation techniques. Is the application using CORS, postMessage, or JSONP?
2. If the site is using CORS, test the strength of the CORS allowlist by submitting test `Origin` headers.
3. If the site is using postMessage, check whether messages can be sent or received as an untrusted site.
4. If the site is using JSONP, try to embed a script tag on an attacker site and request the sensitive data wrapped in
   the JSONP payload.
5. Determine the sensitivity of the information the vulnerability can steal, and whether more is possible.
6. Create report.

## Determine if SOP relaxation techniques are used

Whether the target uses an SOP-relaxation technique shows in the signatures of each one. While browsing a web
application, open the proxy and look for any signs of cross-origin communication. For example, CORS sites will often
return HTTP responses that contain an `Access-Control-Allow-Origin` header.

A site could be using postMessage() if inspecting a page (for example, right-clicking it in Chrome, choosing Inspect,
then navigating to Event Listeners) reveals a message event listener.

And a site could be using `JSONP` if a URL is loaded in a `script` tag with a `callback` function.

## Find CORS misconfiguration

If the site is using CORS:

* Check whether the `Access-Control-Allow-Origin` response header is set to `null`.
* If not, send a request to the site with the origin header `attacker.com`, and check whether the
  `Access-Control-Allow-Origin` in the response is set to `attacker.com`.
* Test whether the site properly validates the origin URL by submitting an Origin header that contains an allowed site,
  such as `www.example.com.attacker.com`. Check the `Access-Control-Allow-Origin` header returns the origin of the
  attacker's domain.
* If one of these `Access-Control-Allow-Origin` header values is returned, that is a CORS misconfiguration. Attackers
  will be able to bypass the SOP and exfiltrate data.

## Find postMessage bugs

If the site is using postMessage:

* Check whether messages can be sent or received as an untrusted site. Create an HTML page with an iframe that frames
  the targeted page accepting messages, and try to send messages to that page that trigger a state-changing behaviour.
* If the target cannot be framed, open it as a new window instead.
* An HTML page that listens for events coming from the target page, then triggers the postMessage from the target site,
  shows whether sensitive data can be received from the target page.

## Find JSONP issues

If the site is using `JSONP`, try to embed a script tag and request the sensitive data wrapped in the JSONP payload.

## Consider mitigating factors

When the target site does not rely on cookies for authentication, these SOP bypass misconfigurations might not be
exploitable. For instance, when the site uses custom headers or secret request parameters to authenticate requests,
those may need forging to exfiltrate sensitive data.

## Escalation

An SOP-bypass bug often means that attackers can read private information or execute action as other users. This means
that these vulnerabilities are often of high severity before any escalation attempts. But SOP-bypass issues can still
be escalated by automation or by pivoting the attack using the information found.

Many researchers will simply report CORS misconfigurations without showing the impact of the vulnerability. Consider the
impact of the issue before sending the report.

## Variants

The CORS misconfigurations are origin reflection (the response echoes any supplied origin), a
trusted `null` origin, trust extended to insecure protocols, and an internal network pivot
where a trusted origin reaches resources behind the perimeter. The
[client-side attacks runbook](../runbooks/client-side.md) covers testing the allowlist and the
related postMessage and JSONP relaxations.

## Resources

* [Portswigger: Same-origin policy (SOP)](https://portswigger.net/web-security/cors/same-origin-policy)
* [OWASP: Cross Site History Manipulation (XSHM)](https://owasp.org/www-community/attacks/Cross_Site_History_Manipulation_(XSHM))
* [Exploiting CORS misconfigurations for Bitcoins and bounties, James Kettle](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [StackStorm - From Originull to RCE - CVE-2019-9580](https://quitten.github.io/StackStorm/)
* [Think Outside the Scope: Advanced CORS Exploitation Techniques](https://infosecwriteups.com/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
* [PayLoadsAllTheThings: CORS miscinfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md)

## Counter moves

Same-origin policy (SOP) is the case here. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defender's view can be found in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
