# Insecure direct object references (IDOR)

Insecure direct object references (IDOR) occur when a developer uses an identifier for direct access to an internal implementation object but provides no additional access control and/or authorisation checks.

* You can automate IDOR hunting by using Burp or your own scripts. 
* You can use the Burp intruder to iterate through IDs to find valid ones. 
* The Burp extension [Autorize](https://github.com/Quitten/Autorize/) scans for authorization issues by accessing higher-privileged accounts with lower-privileged accounts.
* The Burp extensions [Auto Repeater](https://github.com/nccgroup/AutoRepeater/) and [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix/) allow you to automate the process of switching out cookies, headers, and parameters.

For any serious security researcher, seeing an exposed internal identifier is an immediate invitation to test IDOR vulnerabilities, especially as they are a solid source of bug bounty payouts. To identify a potentially insecure object reference, you need to have some idea of how a specific application or website works, how it processes HTTP requests, and what information it should and should not reveal in its HTTP responses. Especially for more advanced vulnerabilities that involve passing data through APIs, detecting IDORs can be tricky.

## Steps

1. Create two accounts for each application role and designate one as the attacker account and the other as the victim account.
2. Discover features in the application that might lead to IDORs. Pay attention to features that return sensitive information or modify user data.
3. Revisit the features you discovered in step 2. With a proxy, intercept your browser traffic while you browse through the sensitive functionalities.
4. With a proxy, intercept each sensitive request and switch out the IDs that you see in the requests. If switching out IDs grants you access to other users’ information or lets you change their data, you might have found an IDOR.
5. Don’t despair if the application seems to be immune to IDORs. Use this opportunity to try a protection-bypass technique. If the application uses an encoded, hashed, or randomised ID, you can try decoding or predicting the IDs. You can also try supplying the application with an ID when it does not ask for one. Finally, sometimes changing the request method type or file type makes all the difference.
6. Monitor for information leaks in export files, email, and text alerts. An IDOR now might lead to an info leak in the future.
7. Draft the report.

## Bypassing protections

IDORs are not always as simple as switching out a numeric ID. As applications become more functionally complex, the way they reference resources also often becomes more complex. Modern web applications have also begun implementing more protection against IDORs, and many now use more complex ID formats. This means that simple, numeric IDORs are becoming rarer.

Some applications use encoding schemes that can easily be reversed. Encode your false IDs by using an
online base64url encoder and executing the IDOR. If you can not tell which encoding scheme the site is using, use the Smart Decode tool in Burp's decoder.

If the application is using a hashed or randomised ID, see if the ID is predictable. Sometimes applications use algorithms that produce insufficient entropy. Try creating a few accounts to analyse how these IDs are created. You might be able to find a pattern that will allow you to predict IDs belonging to other users.

It might also be possible that the application leaks IDs via another API endpoint or other public pages of the application, like the profile page of a user.

In modern web applications, you will commonly encounter scenarios in which the application uses cookies instead of IDs to identify the resources a user can access. And, for the convenience of the developers, for backward compatibility, or just because developers forgot to remove a test feature, some applications will feature an additional way of retrieving resources, using object IDs. If no IDs exist in the application-generated request, try adding one to the request: Append `id`, `user_id`, `message_id`, or other object references to the URL query, or the `POST` body parameters, and see if it makes a difference to the application’s behaviour.

If one HTTP request method does not work, you can try plenty of others instead: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, etc. Applications often enable multiple request methods on the same endpoint but fail to implement the same access control for each method.

Switching the file type of the requested file sometimes leads the server to process the authorisation differently. Applications might be flexible about how the user can identify information: they could allow users to either use IDs to reference a file or use the filename directly. But applications often fail to implement the same access controls for each method of reference.

### A note on blind IDORs

Sometimes endpoints susceptible to IDOR don’t respond with the leaked information directly. They might lead the application to leak information elsewhere instead: in export files, email, and maybe even in text alerts.

## Escalation

The impact of an IDOR depends on the affected function To maximise the severity of the bugs, you should always look for IDORs in critical functionalities first. Both read-based IDORs (which leak information but do not alter the database) and write-based IDORs (which can alter the database in an unauthorised way) can be of high impact.

For state-changing, write-based IDORs, look for IDORs in password reset, password change, and account recovery features, as these often have the highest business impact. Target these over a feature that changes email subscription settings.

For non-state-changing (read-based) IDORs, look for functionalities that handle the sensitive information in the application. For example, look for functionalities that handle direct messages, personal information, and private content. Consider which application functionalities make use of this information and look for IDORs accordingly.

You can also combine IDORs with other vulnerabilities to increase their impact. For example, a write-based IDOR can be combined with self-XSS to form a [stored XSS](xss.md). An IDOR on a password reset endpoint combined with username enumeration can lead to a mass account takeover. Or a write IDOR on an admin account may even lead to [RCE](rce.md).

## Portswigger lab writeups

* [Insecure direct object references](../burp/acl/9.md)

## Remediation

* Replace the insecure direct object references with indirect object references that are then internally mapped to actual objects. This could mean using a temporary per-session reference map populated only with values valid for a specific user and associated with random, non-sequential keys.
* Using secure (salted) hashes instead of actual object references is another way to make it harder for attackers to tamper with user-controllable values.

These mitigations hide internal implementation details but do not address the underlying [access control issues](acl.md). A better approach to eliminating IDOR vulnerabilities is to ensure proper session management and object-level user access control checks. Even if an attacker manages to discover an internal object reference and manipulate it, they will not obtain unauthorised access.

## Resources

* [Portswigger: Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor)
* [OWASP: Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
* [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
* [HackTricks: IDOR](https://book.hacktricks.xyz/pentesting-web/idor)

