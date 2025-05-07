# Broken access control

Broken Access Control occurs when a user able to access or modify information they should not have access to. This could be related to being unauthenticated, or accessing content that the user's role should not have access to. [IDOR (Insecure Direct Object Reference)](idor.md) is considered a broken access control vulnerability in which a user is able to access/modify information they should not be allowed to, typically via changing an integer value. 

Like [application (business) logic errors](business.md), broken access control vulnerabilities are a different beast altogether. Access control determines whether a user is allowed to carry out the action that they are attempting to perform.

* `403 forbidden` is an error that occurs when navigating to a page that requires permissions a user or role does not have. 
* Such errors may be bypassed by converting a `GET` request to a `POST` request, modifying case in the URL path, appending URL encoded punctuation, etc.

## Steps

1. Learn about the target application. The more you understand about the architecture and development process of a web application, the better you will be at spotting these vulnerabilities. Note endpoints which should require authentication and then browse them unauthenticated. This can be automated with Burp Intruder. 
2. Manually intercept requests while browsing the site and pay attention to sensitive functionalities. Keep track of every request sent during these actions. For example check if you can access:

* `/admin/upload` as an authenticated user (non admin)
* `/api/users` unauthenticated
* `/api/user/someone` as another user

3. Use your creativity to think of ways to bypass access control.
4. Think of ways to combine a vulnerability found with other vulnerabilities to maximize the potential impact of the flaw.
5. Draft the report.

## Bypassing protections

Appending `%2e` (URL encoded `.`) or other encoded punctuation:

    http://example.com/./admin/
    http://example.com/admin/.
    http://example.com//admin//
    http://example.com/./admin/..
    http://example.com/;/admin
    http://example.com/.;/admin
    http://example.com//;//admin

## Automation

[Bypass-403](https://github.com/iamj0ker/bypass-403#Bypass-403) is a simple script just made for self use for bypassing 403 and can also be used to compare responses on various conditions.

## Escalation

Bypassing `403 forbidden` pages can give access to admin or elevated privileges, and if reported can result in some great bounties. Escalating broken access control depends entirely on the nature of the flaw found. But a general rule of thumb is to try to combine the broken access control with other vulnerabilities to increase their impact.

* A broken access control that gives access to the admin panel with a console or application deployment capabilities can lead to [remote code execution](rce.md). 
* If you can find the configuration files of a web application, you can search for CVEs for the software versions in use to further compromise the application. 
* You might also find credentials in a file that can be used to access different machines on the network.

Think of ways malicious users can exploit these vulnerabilities to the fullest extent, and communicate their impact in detail in the report.

## Portswigger lab writeups

* [Unprotected admin functionality](../burp/acl/1.md)
* [Unprotected admin functionality with unpredictable URL](../burp/acl/2.md)
* [User role controlled by request parameter](../burp/acl/3.md)
* [User role can be modified in user profile](../burp/acl/4.md)
* [User ID controlled by request parameter](../burp/acl/5.md)
* [User ID controlled by request parameter, with unpredictable user IDs](../burp/acl/6.md)
* [User ID controlled by request parameter with data leakage in redirect](../burp/acl/7.md)
* [User ID controlled by request parameter with password disclosure](../burp/acl/8.md)
* [Insecure direct object references](../burp/acl/9.md)
* [URL-based access control can be circumvented](../burp/acl/10.md)
* [Method-based access control can be circumvented](../burp/acl/11.md)
* [Multistep process with no access control on one step](../burp/acl/12.md)
* [Referer-based access control](../burp/acl/13.md)

## Remediation

* Most frameworks do not yet have the capability of automatically implementing permissions structures. Permissions structures need to be implemented by developers, because every application has specific, custom requirements. In most cases, the reason that access control is broken is that it has not been implemented. 
* When designing a permissions structure for an application, implement a **deny by default** (for all requests to all endpoints), and require allowlisting specific users/roles for any interaction to occur with that endpoint.

## Resources

* [Portswigger: Access control vulnerabilities and privilege escalation](https://portswigger.net/web-security/access-control)
* [OWASP: Broken Access Control](https://owasp.org/www-community/Broken_Access_Control)
* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [Role and Attribute based Access Control for Node.js](https://www.npmjs.com/package/accesscontrol)

