# Cross-site request forgery (CSRF)

* CSRF bugs can exist in GET or POST requests. Using one instead of the other is not a protection, but it requires a little more effort to exploit a POST request. 
* To detect vulnerable GET requests, use the map created by the HTTP Proxy, and look for requests to methods in the application, internal or external.
* Use the `img` tag to test GET requests.
* Create forms to perform actions on vulnerable POST requests, using hidden fields to send the information required by the application.
* Cookies are vulnerable, so always take control of them in the client side.
* Although CSRF is normally described in relation to cookie-based session handling, it can also be done in other contexts where the application automatically adds some user credentials to requests, such as HTTP Basic authentication and certificate-based authentication.
* Pay special attention to APIs. Currently, nearly all developers want to construct service-oriented applications, and those are generally more susceptible to CSRF attacks.

## Steps

1. Look for relevant state-changing actions on the application and keep a note on their locations and functionality.
2. Check these functionalities for CSRF protection. If you can not find any protections, you might have found a vulnerability.
3. There are a lot of anti-CSRF protections, and most of them are included in the most-used web technologies. Avoid reinventing the wheel. If any CSRF protection mechanisms are present, try to bypass the protection.
4. Confirm the vulnerability by crafting a malicious HTML page and visiting that page to see if the action has executed.
5. Think of strategies for delivering the payload to end users.
6. Draft the CSRF report

## Look for state-changing actions

Use the Site map tab in Burp or Zap, to detect when a resource is called to other domains.

Log in to the target site and browse through it in search of any activity that alters data. Go through all the app’s functionalities, clicking all the links. Intercept the generated requests with a proxy like Burp or Zap, and write down their URL endpoints. Record these endpoints one by one, and include whether it is a `POST` or a `GET`, and the `request parameters`.

## Look for a lack of CSRF protections

Most security protection implemented to avoid attacks are based on csrf-tokens. The most frequently used development frameworks, such as Java Struts, .NET, Ruby on Rails, and PHP, include these tokens by default. And there are other methods, which can be bypassed.

### CSRF-unsafe protections

* Secret cookies: Some developers include a cookie with a value to validate that the request received by the application comes from a valid place. But the main problem with the cookies is that they are stored in the client side, so it is possible to get them just by submitting a request using the web browser. These cookies work more as a session identifier than an anti-CSRF token; they are just like adding two session IDs.
* Request restrictions: Some developers limit the type of request received by the application to just accept POST requests, but, it is entirely possible to exploit a CSRF using POST requests.
* Complex flow: Some developers create complex application flows to avoid these kinds of attacks, like confirming critical actions. We just need to understand how the process works using an HTTP proxy, not automating the attack in the same way as the others.
* URL rewriting: To confuse the attackers, some developers rewrite the URLs used in the request, or use named magic URLs, which are URLs rewritten to be shorter and look better when you are managing long paths. And, as all the information is sent into the request, the attacker can just copy and use the same information to perform the attack.
* Using HTTPS instead of HTTP: To protect the request, sometimes, HTTP is used. Never mind, because the Proxy intercepts all the information.

### CSRF - more safe protection

* Form keys: A key included in each request to a URL; so, if a malicious user sent a repeated key, the application would avoid the attack.
* Hashes: It is possible to add hashes for sessions, methods, keys, and so on.
* View state: .NET has implemented a control and named view state, that tracks the user session, but it includes a specific control to avoid manipulation, and also a hash to protect it.
* Referer: The HTTP requests have a header known as referer. You can use it to prevent requests from unexpected sites. However, do not trust a lot on it. Anything can be modified from the client side.
* Tokens: The most extended security control to avoid CSRF is the use of tokens. These are usually hashed identifiers that can also include secret data, such as the referer information, to protect the requests.
* Referer headers can be manipulated by attackers and aren’t a foolproof mitigation solution. Developers should implement a combination of CSRF tokens and `SameSite` session cookies for the best protection.

## Bypassing protections

If the protection used is incomplete or faulty, you might still be able to achieve a CSRF attack with a few modifications to the payload. Create CSRF templates to automate the exploitation to confirm the vulnerabilities. 

    <form method='POST' action='http://targetsite.com/form.php'>
        <input type='hidden' name='criticaltoggle' value='true'
        <input type='submit' value='submit'>
    </form>

* If the endpoint uses CSRF tokens but the page itself is vulnerable to [clickjacking](clickjacking.md), you can exploit clickjacking to achieve the same results as a CSRF, because clickjacking uses an iframe to frame the page in a malicious site while having the state-changing request originate from the legitimate site.
* Change the request method: Sometimes sites will accept multiple request methods for the same endpoint, and protection might not be in place for another method.
* Bypass CSRF tokens stored on the server: Just because a site uses CSRF tokens does not mean it is validating them properly. Try deleting the token parameter or sending a blank token parameter.
* Deleting the token parameter or sending a blank token often works because of a common application logic mistake. Applications sometimes check the validity of the token only if the token exists, or if the token parameter is not blank.
* Some applications might check only whether the token is valid, without confirming that it belongs to the current user. If this is the case, you can insert your own CSRF token into the malicious request.
* Bypass double-submit CSRF tokens: In double-submit cookie as a defence against CSRF, the state-changing request contains the same random token as cookie and request parameter, and the server checks whether the two values are equal. If the values match, the request is seen as legitimate. Nomnomnom.
* In a double-submit token validation system, it does not matter whether the tokens themselves are valid, and the application is probably not keeping records of the valid tokens server-side. If it did, it wouldn't use this scheme.
* Bypass CSRF Referer Header check: If the target site is not using CSRF tokens, the server might verify that the referer header sent with the state-changing request is a part of the website’s `allowlisted_domains`. Sometimes, all you need to do to bypass a referer check is to not send a referer at all. To remove the referer header, add a meta tag to the page hosting the request form.
* What if the application looks for the string "example.com" in the referer URL, and if the referer URL contains that string, the application treats the request as legitimate. Otherwise, it rejects the request? In this case, you can bypass the referer check by placing the victim domain name in the referer URL as a subdomain. You can achieve this by creating a subdomain named after the victim’s domain, and then hosting the malicious HTML on that subdomain. Or try placing the victim domain name in the referer URL as a pathname.
* Using [XSS](xss.md) as helper: In some cases an application an anti-CSRF protection and is well-implemented, but it is possible to defeat the anti-CSRF protection by using an XSS technique. When the application receives the XSS attacks, it will have the token or hash included as protection. The purpose is not injecting the code, but getting the token to use it in other requests.
* A stored XSS could read all the tokens in an application, because a stored XSS is launched by the application, and any response launched by it will have the token – even an XSS launched.
* In applications that have more than one step to perform an action, it is possible that the anti-CSRF protection had been just included in the critical step. If you can perform an XSS attack in one of the unprotected sections, it is possible that you will get the token or hash used for the critical step. It is the first step, by logic, and is used to transfer the user to the second step, so the XSS attack is just following the application's natural flow.
* When the anti-CSRF protection is related with a username not in their session, the only way is to get the credentials in order to exploit the CSRF, not just the token is needed. To do that, one of the last opportunities is an XSS attack to steal the login information, and at the same time retrieve the token by the logic application itself.

## Avoiding problems with authentication

Most CSRF attacks depend on the user session, which needs to be established before performing the actions using the privileged access defined in the user's profile. And some developers include confirmations to perform some actions.

One of the most common examples of this is the change password functionality. Maybe by exploiting a CSRF, a user can upload a new password, but the application could ask for the current password in order to accept the change. This confirmation is really a new authentication.

Add to the form being used to exploit the vulnerability and the feature to ask for a new password, this functionality:

    {# CSRF #}
    {% set csrf = false %}
    {% set target_url = 'https://github.com/securestate/king-phisher' %}
    {% do
    request.parameters.update({
    'username': request.parameters['username'],
    'password': request.parameters['password']
    })
    %}

For bug bounty hunting and pentesting, not a problem, because you just need to confirm that it is possible. For malicious users and red teamers somewhat of a problem, because the forms must look real to victims, to avoid detection.

## Delivering the CSRF payload

The easiest option of delivering a CSRF payload is to trick users into visiting an external malicious site. 

Assume `example.com` has a forum that users frequent. Post a link like this on the forum to encourage users to visit their page:

    Visit this page to get a discount on your example.com subscription:
    https://example.attacker.com

And on `example.attacker.com`, host an auto-submitting form to execute the CSRF:

    <html>
        <form method="POST" action="https://email.example.com/set_password" id="csrf-form">
            <input type="text" name="new_password" value="this_account_is_now_mine">
            <input type='submit' value="Submit">
        </form>
        <script>document.getElementById("csrf-form").submit();</script>
    </html>

For CSRFs executable via a `GET` request, try to embed the request as an image directly, for example, as an image posted to a forum.

    <img src="https://email.example.com/set_password?new_password=mine">

Or deliver a CSRF payload to a large audience by exploiting `stored-XSS`. If the forum comment field suffers from this vulnerability, an attacker can submit a `stored-XSS` JS payload there to make any forum visitor execute the attacker’s malicious script.

    <script>
        document.body.innerHTML += "
            <form method="POST" action="https://email.example.com/set_password" id="csrf-form">
                <input type="text" name="new_password" value="mine">
                <input type='submit' value="Submit">
            </form>";
        document.getElementById("csrf-form").submit();
    </script>

This way, you can show companies how attackers can realistically attack many users and demonstrate the maximum impact of the found CSRF vulnerability. If you have Burp Suite Pro, or use Zap, you can also take advantage of their CSRF POC-generation functionalities.

## Escalation

While the majority of CSRFs are low-severity issues, sometimes a CSRF on a critical endpoint can lead to severe consequences. Escalate CSRFs into severe security issues to maximise their impact.

CSRF can sometimes cause [information leaks](disclosure.md) as a side effect. Applications often send or disclose information according to user preferences. If you can change these settings via CSRF, you can pave the way for sensitive information disclosures.

[Self-XSS](xss.md) is a kind of XSS attack that requires the victim to input the XSS payload. These vulnerabilities are almost always considered a nonissue because they’re too difficult to exploit; doing so requires a lot of action from the victim’s part, and thus you’re unlikely to succeed. But, when you combine CSRF with self-XSS, you can often turn the self-XSS into stored XSS.

Account takeovers are possible when a CSRF vulnerability exists in critical functionality, like the code that creates a password, changes the password, changes the email address, or resets the password.

As an example, assume that in addition to signing up by using an email address and password, `example.com` also allows users to sign up via their social media accounts. If a user chooses this option, they’re not required to create a password, and they can log in via their linked account. To give users another option, those who’ve signed up via social media can set a new password via the following request:

    POST /set_password
    Host: example.com
    Cookie: session_cookie=SESSION_COOKIE;
    
    (POST request body)
    password=XXXXX&csrf_token=871caef0757a4ac9691aceb9aad8b65b

The user signed up via their social media account, and does not need to provide an old password to set the new password, so if CSRF protection fails on this endpoint, an attacker would have the ability to set a password for anyone who signed up via their social media account and has not yet done so.

## Portswigger lab writeups

* [CSRF vulnerability with no defences](../burp/csrf/1.md)
* [CSRF where token validation depends on request method](../burp/csrf/2.md)
* [CSRF where token validation depends on token being present](../burp/csrf/3.md)
* [CSRF where token is not tied to user session](../burp/csrf/4.md)
* [CSRF where token is tied to non-session cookie](../burp/csrf/5.md)
* [CSRF where token is duplicated in cookie](../burp/csrf/6.md)
* [SameSite Lax bypass via method override](../burp/csrf/7.md)
* [SameSite Strict bypass via client-side redirect](../burp/csrf/8.md)
* [SameSite Strict bypass via sibling domain](../burp/csrf/9.md)
* [SameSite Lax bypass via cookie refresh](../burp/csrf/10.md)
* [CSRF where Referer validation depends on header being present](../burp/csrf/11.md)
* [CSRF with broken Referer validation](../burp/csrf/12.md)

## Remediation

* The most common mitigation methods is to generate unique random tokens for every session request or ID. These are subsequently checked and verified by the server. Session requests having either duplicate tokens or missing values are blocked. Alternatively, a request that does not match its session ID token is prevented from reaching an application. Consideration must be given to the user experience when going to that level of tokenisation since users who have multiple tabs will find that requests on outdated tabs no longer validate, and using the back button will break the session flow.
* Double submission of cookies is another well-known method to block CSRF. Similar to using unique tokens, random tokens are assigned to both a cookie and a request parameter. The server then verifies that the tokens match before granting access to the application.
* Anti-CSRF token protection is the best safeguard against CSRF attacks, but for example, web applications that have a vulnerability to [cross-site scripting (XSS) attacks](xss.md), it may be possible to execute a script that exposes the new form token which defeats the protection offered by the CSRF token.

All in all, tokens can be exposed at a number of points, including in browser history, HTTP log files, network appliances logging the first line of an HTTP request and referrer headers, if the protected site links to an external URL. These potential weak spots make tokens a less than full-proof solution. To provide the most effective web application security, consider and evaluate all vulnerabilities. 

## Resources

* [Portswigger: CSRF](https://portswigger.net/web-security/csrf)
* [OWASP: Testing for Cross Site Request Forgery](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
* [CSRF proof of concept with OWASP ZAP](https://resources.infosecinstitute.com/topic/csrf-proof-of-concept-with-owasp-zap/)
* [Portswigger: Generate CSRF PoC](https://portswigger.net/burp/documentation/desktop/functions/generate-csrf-poc)


