# Open redirection

Sites often use HTTP or URL parameters to redirect users to a specified URL without any user action. While this behaviour can be useful, it can also cause open redirects, which happen when an attacker is able to manipulate the value of this parameter to redirect the user offsite.

* Open redirects are generated due to an incorrect URL validation in the application.
* The most common consequence is phishing.
* In some cases, the behaviour depends on the browser used to interact with the application. It is because some methods used by the developers to create the redirections just work in a few browsers. Open redirects are most common in Internet Explorer.

## Steps

1. Search for redirect URL parameters. These might be vulnerable to parameter-based open redirect.
2. Search for pages that perform referer-based redirects. These are candidates for a referer-based open redirect.
3. Test the pages and parameters found for open redirects.
4. If the server blocks the open redirect, try protection bypass techniques.
5. Brainstorm ways of using the open redirect in other bug chains.

There are some redirections that are easy to detect – most redirections use a GET request. Others are a little more difficult to detect in simple view and need the use of the HTTP proxy to confirm them.

## Look for redirect parameters

Start by searching for the parameters used for redirects:

    https://example.com/login?redirect=https://example.com/dashboard
    https://example.com/login?redir=https://example.com/dashboard
    https://example.com/login?next=https://example.com/dashboard
    https://example.com/login?next=/dashboard

Redirections using JavaScript:

    window.open('http://example.com')
    location.replace('http://example.com')
    location.assign('http://example.com')
    location.href='http://example.com'
    location='http://example.com'
    location.port='8080'
    document.URL()
    URL

Open your proxy while you browse the website. Then, in HTTP history, look for any parameter that contains absolute or relative URLs.

Also take note of the pages that do not contain redirect parameters in their URLs but still automatically redirect their users. These pages are candidates for referer-based open redirects. To find these pages, keep an eye out for `3XX` response codes like `301` and `302`. These response codes indicate a redirect.

## Use Google Dorks

Google dorking is an efficient way to find redirect parameters. To look for redirect parameters on a target site, start by setting the site search term to your target site:

    site:example.com

Then look for pages that contain URLs in their URL parameters, making use of `%3D`, the URL-encoded version of the equal sign (`=`):

    inurl:%3Dhttp site:example.com

Also try using `%2F`, the URL-encoded version of the slash (`/`) to get relative URLs:

    inurl:%3D%2F site:example.com

And search for the names of common URL redirect parameters:

    inurl:redir site:example.com
    inurl:redirect site:example.com
    inurl:redirecturi site:example.com
    inurl:redirect_uri site:example.com
    inurl:redirecturl site:example.com
    inurl:redirect_url site:example.com
    inurl:return site:example.com
    inurl:returnurl site:example.com
    inurl:relaystate site:example.com
    inurl:forward site:example.com
    inurl:forwardurl site:example.com
    inurl:forward_url site:example.com
    inurl:url site:example.com
    inurl:uri site:example.com
    inurl:dest site:example.com
    inurl:destination site:example.com
    inurl:next site:example.com

## Test for parameter-based open redirects

Investigate the functionality of each redirect parameter found and test each one for an open redirect. Insert a random hostname, or a hostname you own, into the redirect parameters; then see if the site automatically redirects to the site specified.

Some sites will redirect to the destination site immediately, others require a user action first.

## Test for referer-based open redirects

Set up a page on a domain you own and host this HTML page:

    <html>
        <a href="https://example.com/login">Click on this link!</a>
    </html>

Replace the linked URL with the target page. Then reload and visit your HTML page. Click the link and see if you get redirected to your site automatically or after the required user interactions.

## Bypassing protections

Sites prevent open redirects by validating the URL used to redirect the user, making the root cause of open redirects failed URL validation. And, URL validation is extremely difficult to get right.

Sometimes validators do not account for all the edge cases that can cause the browser to behave unexpectedly. In this case, try to bypass the protection by using a few strategies.

Modern browsers often autocorrect URLs that do not have the correct components, in order to correct mangled URLs caused by user typos.

    https:attacker.com
    https;attacker.com
    https:\/\/attacker.com
    https:/\/\attacker.com

As a common defence against open redirects, the URL validator often checks if the redirect URL starts with, contains, or ends with the site's domain name. This type of protection can be bypassed by creating a subdomain or directory with the target’s domain name:

    https://example.com/login?redir=http://example.com.attacker.com
    https://example.com/login?redir=http://attacker.com/example.com

The validator might accept only URLs that both start and end with a domain listed on the allowlist.
This URL satisfies both of these rules:

    https://example.com/login?redir=https://example.com.attacker.com/example.com

Or you could use the at symbol (`@`) to make the first `example.com` the `username` portion of the URL:

    https://example.com/login?redir=https://example.com@attacker.com/example.com

Especially custom-built URL validators are prone to attacks like these, because developers did not consider all edge cases. Too agile maybe?

You can also manipulate the scheme portion of the URL to try to fool the validator.

    data:MEDIA_TYPE[;base64],DATA

Use the `data:` scheme to construct a base64-encoded redirect URL that evades the validator.

When validators validate URLs, or when browsers redirect users, they have to first find out what is contained in the URL by decoding any characters that are URL encoded. If there is any inconsistency between how the validator and browsers decode URLs, this can be exploited.

Try to double- or triple-URL-encode certain special characters (like the slash) in the payload. if the validator does not double-decode URLs, but the browser does, you can use a payload like this:

    https://attacker.com%252f@example.com

Non-ASCII characters (`%ff` is the character `ÿ`, a non-ASCII character):

    https://attacker.com%ff.example.com

The validator has determined that `example.com` is the domain name, and `attacker.comÿ` is the
subdomain name.

Sometimes browsers decode non-ASCII characters into question marks:

    https://attacker.com?.example.com

Another common scenario is that browsers will attempt to find a “most alike” character (the (`╱`) here is `%E2%95%B1`):

    https://attacker.com╱.example.com

You can also use character sets in other languages to bypass filters, like [Unicode](http://www.unicode.org/charts/).

To defeat more-sophisticated URL validators, combine multiple strategies to bypass layered defences, like:

    https://example.com%252f@attacker.com/example.com

## Escalation

Attackers could use open redirects by themselves to make their phishing attacks more credible. For example, they could send this URL in an email to a user: 

    https://example.com/login?next=https://attacker.com/fake_login.html

Though this URL would first lead users to the legitimate website, it would redirect them to the attacker’s site after login. The attacker could host a fake login page on a malicious site that mirrors the legitimate site’s login page, and prompt the user to log in again. Believing they’ve entered an incorrect password, the user would provide their credentials to the attacker’s site. At this point, the attacker’s site could even redirect the user back to the legitimate site to keep the victim from realizing that their credentials were stolen.

An open redirect can help you bypass URL blocklists and allowlists:

    https://example.com/?next=https://attacker.com/

This URL will pass even well-implemented URL validators, because the URL is technically still on the legitimate website. Open redirects can, therefore, help you maximize the impact of vulnerabilities like server-side request forgery (SSRF).

Open redirects can also be used to steal credentials and OAuth tokens. When a page redirects to another site, browsers will often include the originating URL as a referer HTTP request header. When the originating URL contains sensitive information (authentication tokens), attackers can induce an open redirect to steal the tokens via the referer header.

## Portswigger lab writeups

* [DOM-based open redirection](../burp/dom/4.md)
* [DOM XSS using web messages and a JavaScript URL](../burp/dom/2.md)
* [SSRF with filter bypass via open redirection vulnerability](../burp/ssrf/4.md)
* [Stealing OAuth access tokens via an open redirect](../burp/oauth/4.md)

## Remediation

Avoid dynamically setting redirection targets using data that originated from any untrusted source. 

Force redirects to first go to a page that notify users they are redirected out of the website. The message should clearly display the destination and ask users to click on a link to confirm that they want to move to the new destination.

## Resources

* [RootMe: Understanding and Discovering Open Redirect Vulnerabilities](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Understanding%20and%20Discovering%20Open%20Redirect%20Vulnerabilities%20-%20Trustwave.pdf)
* [Portswigger: Using Burp to Test for Open Redirections](https://portswigger.net/support/using-burp-to-test-for-open-redirections)
* [OWASP: Testing for Client-side URL Redirect](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
* [swisskyrepo/PayloadsAllTheThings/Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
* [PentesterLand: Open Redirect Cheat Sheet](https://pentester.land/blog/open-redirect-cheatsheet/)
* [cujanovic/Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
* [HackTricks: Open redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)

