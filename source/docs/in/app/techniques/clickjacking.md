# Clickjacking

Clickjacking is a technique where a user clicks on a malicious link without realising. This is usually done with a transparent layer on the original site that uses JavaScript or CSS, but if you have control of a subdomain that is trusted by the user, an attacker can socially engineer users to click on the malicious link.

## Steps

1. Spot the state-changing actions on the website and keep a note of their URL locations. Mark the ones that require only mouse clicks to execute for further testing.
2. Check these pages for the `X-Frame-Options`, `Content-Security-Policy` header, and a `SameSite` session cookie. If you can’t spot these protective features, the page might be vulnerable.
3. Craft an HTML page that frames the target page, and load that page in a browser to see if the page has been framed.
4. Confirm the vulnerability by executing a simulated clickjacking attack on your own test account.
5. Craft a sneaky way of delivering your payload to end users, and consider the larger impact of the vulnerability.
6. Draft the report.

## Look for state-changing actions

Clickjacking vulnerabilities are valuable only when the target page contains state-changing actions. Look for pages that allow users to make changes to their accounts, like changing their account details or settings. Also check that the action can be achieved via clicks alone.

## Check the Response Headers

Go through each of the state-changing functionalities found and revisit the pages that contain them. Turn on a [proxy](https://testlab.tymyrddin.dev/docs/webapp/proxies) and intercept the HTTP response that contains that web page. See if the page is being served with the `X-Frame-Options` or `Content-Security-Policy` header.

If the page is served without any of these headers, it may be vulnerable to clickjacking. And if the state-changing action requires users to be logged in when it is executed, you should also check if the site uses SameSite cookies. If it does, you won’t be able to exploit a clickjacking attack on the site’s features that require authentication.

You can confirm that a page is frameable by creating an HTML page that frames the target page. If the target page shows up in the frame, the page is frameable:

    <html>
    <head>
    <title>Clickjack test page</title>
    </head>
    <body>
    <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
    <iframe src="PAGE_URL" width="500" height="500"></iframe>
    </body>
    </html>

## Confirm the vulnerability

Confirm the vulnerability by executing a clickjacking attack on the test account. Try to execute the state-changing action through the framed page you just constructed and see if the action succeeds.

## Bypassing protections

Clickjacking is not possible when the site implements the proper protections. If a modern browser displays an X-Frame-Options protected page, chances are you can not exploit clickjacking on the page, and you will have to find another vulnerability, such as XSS or CSRF, to achieve the same results. Sometimes, the page does not show up in your test iframe even though it lacks the headers that prevent clickjacking. If the website itself fails to implement complete clickjacking protections, you might be able to bypass the mitigations.

* If the website uses frame-busting techniques instead of HTTP response headers and SameSite cookies: find a loophole in the frame-busting code. For instance, developers commonly make the mistake of comparing only the top frame to the current frame when trying to detect whether the protected page is framed by a malicious page.
* If the top frame has the same origin as the framed page, developers may allow it, because they deem the framing site’s domain to be safe. In this case, search for a location on the victim site that allows you to embed custom iframes. Common features that require custom iframes are those that allow you to embed links, videos, audio, images, and custom advertisements and web page builders.
* The double iframe trick works by framing a malicious page within a page in the victim’s domain. First, construct a page that frames the victim’s targeted functionality. Then place the entire page in an iframe hosted by the victim site. This way, both `top.location` and `self.location` point to `victim.com`.
* In general, look for the edge cases a developer did not include.

## Escalation

Websites often serve pages without clickjacking protection. As long as the page does not contain exploitable actions, the lack of clickjacking protection is not considered a vulnerability. On the other hand, if the frameable page contains sensitive actions, the impact of clickjacking can be correspondingly severe.

Focus on the application’s most critical functionalities to achieve maximum business impact. You can also combine multiple clickjacking vulnerabilities or chain clickjacking with other bugs to pave the way to more severe security issues.

## Portswigger lab writeups

* [Basic clickjacking with CSRF token protection](../burp/clickjacking/1.md)
* [Clickjacking with form input data prefilled from a URL parameter](../burp/clickjacking/2.md)
* [Clickjacking with a frame buster script](../burp/clickjacking/3.md)
* [Exploiting clickjacking vulnerability to trigger DOM-based XSS](../burp/clickjacking/4.md)
* [Multistep clickjacking](../burp/clickjacking/5.md)

## Remediation

Frame busting scripts are busted: It is often easy for an attacker to circumvent these protections.

Clickjacking is a browser-side behaviour and its success depends on browser functionality and conformity to prevailing web standards and best practice. Server-side protection against clickjacking can be provided by defining and communicating constraints over the use of components such as iframes. And implementation of protection depends upon browser compliance and enforcement of these constraints. Two mechanisms for server-side clickjacking protection are `X-Frame-Options` and `Content Security Policy`. 

`X-Frame-Options` is not implemented consistently across browsers, but when properly applied in conjunction with `Content Security Policy` as part of a multi-layer defense strategy it can provide effective protection against clickjacking attacks. 

The recommended clickjacking protection is to incorporate the frame-ancestors directive in the application's `Content Security Policy`. The frame-ancestors `none` directive is similar in behaviour to the `X-Frame-Options` `deny` directive. The frame-ancestors `self` directive is broadly equivalent to the `X-Frame-Options` `sameorigin` directive. 

The following CSP whitelists frames to the same domain only: 

```text
Content-Security-Policy: frame-ancestors 'self';
```

Framing can also be restricted to named sites:

```text
Content-Security-Policy: frame-ancestors normal-website.com;
```

To be effective against clickjacking and XSS, CSPs need careful development, implementation and testing and should be used as part of a multi-layer defense strategy. 

## Resources

* [Portswigger: Clickjacking (UI redressing)](https://portswigger.net/web-security/clickjacking)
* [OWASP: Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
* [HackTricks: Clickjacking](https://book.hacktricks.xyz/pentesting-web/clickjacking)


