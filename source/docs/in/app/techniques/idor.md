# Insecure direct object references (IDOR)

Insecure direct object references (IDOR) occur when a developer uses an identifier for direct access to an internal
implementation object but provides no additional access control and/or authorisation checks.

* IDOR hunting can be automated with Burp or custom scripts.
* The Burp intruder iterates through IDs to find valid ones.
* The Burp extension [Autorize](https://github.com/Quitten/Autorize/) scans for authorisation issues by accessing
  higher-privileged accounts with lower-privileged accounts.
* The Burp extensions [Auto Repeater](https://github.com/nccgroup/AutoRepeater/)
  and [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix/) automate the process of switching out cookies,
  headers, and parameters.

For any serious security researcher, seeing an exposed internal identifier is an immediate invitation to test IDOR
vulnerabilities, especially as they are a solid source of bug bounty payouts. Identifying a potentially insecure object
reference takes some idea of how a specific application or website works, how it processes HTTP requests, and what
information it is and is not meant to reveal in its HTTP responses. Especially for more advanced vulnerabilities that
involve passing data through APIs, detecting IDORs can be tricky.

## Steps

1. Create two accounts for each application role and designate one as the attacker account and the other as the victim
   account.
2. Discover features in the application that might lead to IDORs. Pay attention to features that return sensitive
   information or modify user data.
3. Revisit the features discovered in step 2. With a proxy, intercept the browser traffic while browsing through the
   sensitive functionalities.
4. With a proxy, intercept each sensitive request and switch out the IDs in the requests. If switching IDs grants access
   to other users’ information or alters their data, that may be an IDOR.
5. Where the application seems immune to IDORs, try a protection-bypass technique. Where the application uses an encoded,
   hashed, or randomised ID, decoding or predicting the IDs is worth a try, as is supplying an ID when the application
   does not ask for one. Sometimes changing the request method type or file type makes all the difference.
6. Monitor for information leaks in export files, email, and text alerts. An IDOR now might lead to an info leak in the
   future.
7. Draft the report.

## Bypassing protections

IDORs are not always as simple as switching out a numeric ID. As applications become more functionally complex, the way
they reference resources also often becomes more complex. Modern web applications have also begun implementing more
protection against IDORs, and many now use more complex ID formats. This means that simple, numeric IDORs are becoming
rarer.

Some applications use encoding schemes that can easily be reversed. Encode the false IDs with an online base64url
encoder and execute the IDOR. Where the encoding scheme is unclear, the Smart Decode tool in Burp's decoder helps.

If the application is using a hashed or randomised ID, check whether the ID is predictable. Sometimes applications use
algorithms that produce insufficient entropy. Creating a few accounts to analyse how the IDs are formed can reveal a
pattern that predicts IDs belonging to other users.

It might also be possible that the application leaks IDs via another API endpoint or other public pages of the
application, like the profile page of a user.

In modern web applications, a common pattern is the application using cookies instead of IDs to identify the resources a
user can access. For developer convenience, for backward compatibility, or just because a test feature was never
removed, some applications keep an additional way of retrieving resources by object ID. Where no IDs exist in the
application-generated request, adding one is worth trying: append `id`, `user_id`, `message_id`, or other object
references to the URL query or the `POST` body parameters, and watch whether the application’s behaviour changes.

If one HTTP request method does not work, plenty of others are worth trying instead: `GET`, `POST`, `PUT`, `DELETE`,
`PATCH`. Applications often enable multiple request methods on the same endpoint but fail to implement the same access
control for each method.

Switching the file type of the requested file sometimes leads the server to process the authorisation differently.
Applications might be flexible about how a user identifies information: they could allow either an ID to reference a file
or the filename directly. But applications often fail to implement the same access controls for each method of
reference.

### A note on blind IDORs

Sometimes endpoints susceptible to IDOR don’t respond with the leaked information directly. They might lead the
application to leak information elsewhere instead: in export files, email, and maybe even in text alerts.

## Escalation

The impact of an IDOR depends on the affected function. To maximise severity, look for IDORs in critical functionalities
first. Both read-based IDORs (which leak information but do not alter the database) and write-based IDORs (which can
alter the database in an unauthorised way) can be of high impact.

For state-changing, write-based IDORs, look for IDORs in password reset, password change, and account recovery features,
as these often have the highest business impact. Target these over a feature that changes email subscription settings.

For non-state-changing (read-based) IDORs, look for functionalities that handle the sensitive information in the
application. For example, look for functionalities that handle direct messages, personal information, and private
content. Consider which application functionalities make use of this information and look for IDORs accordingly.

IDORs can also be combined with other vulnerabilities to increase their impact. For example, a write-based IDOR can be
combined with self-XSS to form a [stored XSS](xss.md). An IDOR on a password reset endpoint combined with username
enumeration can lead to a mass account takeover. Or a write IDOR on an admin account may even lead to [RCE](rce.md).

## Variants

The canonical case is a resource served by an identifier supplied in the request, with no
check that the identifier belongs to the caller. The variations are in the identifier itself:
sequential, encoded, hashed, or predictable, sometimes leaked through another endpoint, and
sometimes reachable only by adding an identifier the application did not expect. The
[access control testing runbook](../runbooks/access-control.md) covers the systematic sweep.

## Resources

* [Portswigger: Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor)
* [OWASP: Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
* [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

## Counter moves

Insecure direct object references (IDOR) is what this page works through. These come back to the same answers: validated
input, encoded output, server-side authorisation, and patched dependencies. The defensive counterpart is in the blue
notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
