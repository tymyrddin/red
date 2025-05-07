# Authentication vulnerabilities

The majority of threats related to the authentication process are associated with passwords and password-based authentication methods. But broken authentication also causes a significant amount of vulnerabilities. Broken authentication occurs when the implementation of the authentication process is flawed. This is usually hard to discover, and can be more severe than the risks associated with passwords.

## Steps

For finding the most common authentication-based vulnerabilities, check:

1. Username enumeration.
2. Weak credentials.
3. Try a brute-force attack.
4. HTTP basic authentication.
5. Poor session management.
6. Staying logged in.
7. SQLi.
8. Insecure password change and recovery.
9. Flawed two-factor authentication.
10. Vulnerable authentication logic.
11. Human negligence.

## Username enumeration

Username enumeration is not exactly an authentication vulnerability. But, it can make life easier by lowering the cost for other attacks, such as brute-force attacks or weak credential checks.

## Weak credential check

Try common credentials like admin, admin1, and password1, and passwords typical for the organisation under investigation. With no restrictions on weak passwords, even sites protected against brute-force attacks can find themselves compromised.

## Brute force attack

If there is a flawed brute-force protection system such as a flaw in the authentication logic, firewall, or secure shell (SSH) protocol, you can hijack login credentials and processes.

## HTTP basic authentication

HTTP basic authentication is simple, sending a username and password with each request. And if security protocols such as TLS session encryption are not used for all communication, the username and password information can be sent in the clear, making it easy to steal the credentials.

The included credentials contain little context, and can easily be misused in attacks such as cross-site request forgeries (CSRF). And because they are included with every single request, modern browsers normally cache this information indefinitely, with minimal ability to "log out", making it easy to reuse the credentials.

## Session management

There are several session mismanagement vulnerabilities such as no session timeouts, exposure of session IDs in URLs, session cookies without the `Http-Only` flag set, and poor session invalidation. Seizing control of an existing session, it is possible to get into a system by assuming the identity of an already-authenticated user, bypassing the authentication process entirely. 

## Staying logged in

A **Remember me** or **Keep me logged in** checkbox beneath a login form makes it super easy for users to stay logged in after closing a session. It generates a cookie that lets users skip the process of logging in.

And this can lead to a cookie-based authentication vulnerability if it is possible to predict a cookie or deduce its generation pattern. This opens the door to malicious techniques like brute-force attacks to predict cookies, and cross-site scripting (XSS) to hack user accounts by allowing a malicious server to make use of a legitimate cookie.

If a cookie is poorly designed or protected, it may be possible to obtain passwords or other sensitive (and legally protected) data such as user addresses or account information from a stored cookie.

## SQL injection

SQL injections can enable attacks on authentication mechanisms by stealing relevant data (such as poorly protected password hashes) from an unprotected database. They can also bypass authentication mechanisms if the injected SQL code is executed by an internal (and already authorised) tool that failed to sufficiently validate external input.

## Insecure password change and recovery

The password reset process poses an authentication vulnerability if an application uses a weak password recovery mechanism such as easy security questions, no CAPTCHAs, or password reset e-mails with overly long or no timeouts.

If the password recovery functionality is flawed, it may be possible to use brute-force techniques or access to other compromised accounts to gain access to user accounts and credentials that are well-protected under normal circumstances.

## Flawed two-factor authentication

While two-factor authentication (2FA) is effective for secure authentication, it can cause critical security issues if not well-implemented.

Attackers can figure out the four- and six-digit 2FA verification codes through SIM swap attacks if they are sent through SMS. Some two-factor authentication is also not truly two-factor; if a user is attempting to access sensitive information on a stolen phone using cached credentials, a "second factor" that sends a message to that same phone adds no additional security.

Two-factor authentication vulnerabilities can also occur if there’s no brute-force protection to lockout an account after a specific number of attempted logins.

## Vulnerable authentication logic

Logic vulnerabilities are common in software applications as a result of poor coding or design that affects authentication and authorisation access, and application functionality.

## Human negligence

Sorry, this list is too long, and not very useful in a pentesting or bug hunting setting. In red teaming however ... :)

## Escalation

Authentication vulnerabilities have serious impact because they can be used to:

* Steal sensitive information
* Masquerade as a legitimate user
* Gain control of the application
* Gain further access
* Destroy the system

## Portswigger lab writeups

* [Username enumeration via different responses](../burp/auth/1.md)
* [2FA simple bypass](../burp/auth/2.md)
* [Password reset broken logic](../burp/auth/3.md)
* [Username enumeration via subtly different responses](../burp/auth/4.md)
* [Username enumeration via response timing](../burp/auth/5.md)
* [Broken brute-force protection, IP block](../burp/auth/6.md)
* [Username enumeration via account lock](../burp/auth/7.md)
* [2FA broken logic](../burp/auth/8.md)
* [Brute-forcing a stay-logged-in cookie](../burp/auth/9.md)
* [Offline password cracking](../burp/auth/10.md)
* [Password reset poisoning via middleware](../burp/auth/11.md)
* [Password brute-force via password change](../burp/auth/12.md)
* [Broken brute-force protection, multiple credentials per request](../burp/auth/13.md)
* [2FA bypass using a brute-force attack](../burp/auth/14.md)

## Remediation

* Use monitoring and IDS/IPS systems.
* Apply HSTS to force web sessions to use TLS encryption, preventing sensitive information from being accessed in transit.
* By generating the same error for a login failure whether the username was valid or invalid, you force an attacker to brute-force not just the set of possible passwords, but also the set of likely usernames, rather than sticking to the ones they know are valid.
* `HttpOnly` and `SameSite` tags protect cookie headers from XSS and CSRF attacks, respectively.
* Review code to check all verifications are in place.
* Audit code regularly to discover logic flaws and authentication bypasses and strengthen your security posture.
* MFA protects applications by using a second source of validation before granting access to users.
* Standard authentication methods, including MFA, ask users for specific credentials whenever they try to log in or access corporate resources. Adaptive Authentication asks for different credentials, depending upon the situation — tightening security when the risk of breach is higher.

## Resources

* [Portswigger: How to secure your authentication mechanisms](https://portswigger.net/web-security/authentication/securing)