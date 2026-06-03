# Clickjacking

Clickjacking is a technique where a user clicks on a malicious link without realising. This is usually done with a
transparent layer on the original site that uses JavaScript or CSS; where an attacker controls a subdomain trusted by
the user, social engineering can lure users into clicking the malicious link.

## Steps

1. Spot the state-changing actions on the website and keep a note of their URL locations. Mark the ones that require
   only mouse clicks to execute for further testing.
2. Check these pages for the `X-Frame-Options`, `Content-Security-Policy` header, and a `SameSite` session cookie. If
   these protective features are absent, the page might be vulnerable.
3. Craft an HTML page that frames the target page, and load that page in a browser to see if the page has been framed.
4. Confirm the vulnerability by executing a simulated clickjacking attack on a test account.
5. Craft a sneaky way of delivering the payload to end users, and consider the larger impact of the vulnerability.
6. Draft the report.

## Look for state-changing actions

Clickjacking vulnerabilities are valuable only when the target page contains state-changing actions. Look for pages that
allow users to make changes to their accounts, like changing their account details or settings. Also check that the
action can be achieved via clicks alone.

## Check the Response Headers

Go through each of the state-changing functionalities found and revisit the pages that contain them. Turn on a proxy and
intercept the HTTP response that contains that web page. See if the page is being served with the `X-Frame-Options` or
`Content-Security-Policy` header.

If the page is served without any of these headers, it may be vulnerable to clickjacking. And if the state-changing
action requires users to be logged in when it is executed, the site's use of SameSite cookies is worth checking too:
where they are present, a clickjacking attack on authenticated features will not work.

A page can be confirmed frameable by creating an HTML page that frames the target page. If the target page shows up in
the frame, the page is frameable:

```html
<html lang="">
    <head>
        <title>Clickjack test page</title>
    </head>
    <body>
        <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
        <iframe src="PAGE_URL" width="500" height="500"></iframe>
    </body>
</html>
```

## Confirm the vulnerability

Confirm the vulnerability by executing a clickjacking attack on the test account. Try to execute the state-changing
action through the framed page just constructed and see whether the action succeeds.

## Bypassing protections

Clickjacking is not possible when the site implements the proper protections. If a modern browser displays an
X-Frame-Options protected page, chances are clickjacking is not exploitable on the page, and another vulnerability,
such as XSS or CSRF, would be needed to achieve the same results. Sometimes the page does not show up in the test
iframe even though it lacks the headers that prevent clickjacking. Where the website fails to implement complete
clickjacking protections, the mitigations may be bypassable.

* If the website uses frame-busting techniques instead of HTTP response headers and SameSite cookies: find a loophole in
  the frame-busting code. For instance, developers commonly make the mistake of comparing only the top frame to the
  current frame when trying to detect whether the protected page is framed by a malicious page.
* If the top frame has the same origin as the framed page, developers may allow it, because they deem the framing site’s
  domain to be safe. In this case, search for a location on the victim site that allows custom iframes to be embedded.
  Common features that require custom iframes are those that embed links, videos, audio, images, and custom
  advertisements and web page builders.
* The double iframe trick works by framing a malicious page within a page in the victim’s domain. First, construct a
  page that frames the victim’s targeted functionality. Then place the entire page in an iframe hosted by the victim
  site. This way, both `top.location` and `self.location` point to `victim.com`.
* In general, look for the edge cases a developer did not include.

## Escalation

Websites often serve pages without clickjacking protection. As long as the page does not contain exploitable actions,
the lack of clickjacking protection is not considered a vulnerability. On the other hand, if the frameable page contains
sensitive actions, the impact of clickjacking can be correspondingly severe.

Focus on the application’s most critical functionalities to achieve maximum business impact. Multiple clickjacking
vulnerabilities can also be combined, or clickjacking chained with other bugs, to pave the way to more severe security
issues.

## Variants

The cases worth knowing are basic framing of a page that relies on CSRF tokens alone, forms
prefilled from a URL parameter so the overlay submits attacker-chosen values, frame-buster
scripts that can be defeated, clickjacking used to trigger DOM-based XSS, and multistep
overlays that walk the victim through several clicks. The
[client-side attacks runbook](../runbooks/client-side.md) covers framing and the bypasses.

## Resources

* [Portswigger: Clickjacking (UI redressing)](https://portswigger.net/web-security/clickjacking)
* [OWASP: Testing for Clickjacking](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking)
* [HackTricks: Clickjacking](https://book.hacktricks.xyz/pentesting-web/clickjacking)

## Counter moves

Clickjacking is the case here. These come back to the same answers: validated input, encoded output, server-side
authorisation, and patched dependencies. Seen from the other side, this sits in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
