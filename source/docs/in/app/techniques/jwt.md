# JSON web tokens attacks

JSON Web Tokens (JWT) are one of the most frequently used methods to exchange information with REST APIs. JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. And it is also frequently misconfigured and abused.

## Steps

* Find JWT tokens
* Identify a test page: Find a request of a page with JWT token which gives a clear response. Profile pages are a good start.
* Check for test cases on the page:
  * Check if the same token still works (it may have expired)
  * Algorithm manipulation: Using None as the algorithm; or using symmetric encryption (HMAC) instead of asymmetric RSA.
  * Lack of signature validation.
  * Bruteforcing weak secret keys.
  * Secret keys leaking through another attack (like [directory traversal](traversal.md), [XXE](xxe.md), or [SSRF](ssrf.md)).
  * Key ID (KID) manipulation: [Directory traversals](traversal.md); [SQL injections](sqli.md); and [Command injections](rce.md).
  * `JKU/JWK/x5u/x5c` headers used sending rogue keys.
  * Information leaks in JWT when developers mistake base64 encoding for encrypting.

## Finding JWT tokens

Use Regex to search in proxy history:

    "[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*"
    "[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*"

## Escalation

The impact of JWT attacks is usually severe. If an attacker is able to create their own valid tokens with arbitrary values, they may be able to escalate their own privileges or impersonate other users, taking full control of their accounts. 

## Portswigger labs

* [JWT authentication bypass via unverified signature](../burp/jwt/1.md)
* [JWT authentication bypass via flawed signature verification](../burp/jwt/2.md)
* [JWT authentication bypass via weak signing key](../burp/jwt/3.md)
* [JWT authentication bypass via jwk header injection](../burp/jwt/4.md)
* [JWT authentication bypass via jku header injection](../burp/jwt/5.md)
* [JWT authentication bypass via kid header path traversal](../burp/jwt/6.md)
* [JWT authentication bypass via algorithm confusion](../burp/jwt/7.md)
* [JWT authentication bypass via algorithm confusion with no exposed key](../burp/jwt/8.md)

## Remediation

### When issuing a token

* Except in very few cases (when used in the client side, for carrying GUI state data and session information) a token is not be issued without a signature. This allows token consumers to trust it and to ensure that it has not been tampered with.
* Use asymmetric signing algorithms if possible. These simplify the key custody. When choosing a symmetric key signing algorithm, take into account that symmetric key algorithms are vulnerable to brute force attacks if the key isn’t strong enough. 
* A JWT, once signed, is valid forever if no expiration date is given (claim `exp`). For Access tokens, anybody capturing the token will have access to the granted operations forever. Assigning identifiers (claim `jti`) to tokens allows for their revocation; in case the token is compromised it is very helpful to be able to revoke the token.
* To ease the management of the tokens to the recipients it is mandatory to identify the issuer (`iss` claim) and all possible recipients (claim `aud`); with this information it will be easy for recipients to locate the signature key and check the token was issued for them (and it is best practice for recipients to validate these claims).
* JWTs are not encrypted by default, so care must be taken with the information included inside the token. If sensitive information must be included inside a token, encrypt the JWT.

### When validating a token

* The signature is the only way to verify that the data contained inside the token has not been tampered with. After validating the token format, check that it has a signature, to prevent scenarios in which an adversary intercepts the token, removes the signature, modifies the data and resends it. DO NOT accept tokens with `alg: "none"` in its header. Always validate that the `alg` claim contains a value from a set of expected values. And the smaller the set, the better.
* Never trust the received claims, especially when using them for searches in backends. The `kid` claim can be used for signing key lookup: Sanitise its value to avoid SQL injection attacks. Similarly, the `jku` (URL to a JWK Set) and `x5u` (URL to an X.509 certification chain) fields can contain arbitrary urls and cause SSRF attacks if used without proper validation, for example by using a whitelist of allowed URLs.
* Before accepting a JWT, verify that the token was issued by the expected entity (`iss` claim) and that it was issued for the intended audience (`aud` claim); this will reduce the risk of an adversary using a token intended for another recipient, and gaining unauthorised access to resources.
* When looking up the signing key, check that the signing algorithm is valid for the issuer. An adversary could intercept a token using an RS256 algorithm, modify it and create a signature using the public key of the issuer by using a HS256 algorithm. 

## Resources

* [RFC7519](https://repository.root-me.org/RFC/EN%20-%20rfc7519.txt)
* [Portswigger: JWT attacks](https://portswigger.net/web-security/jwt)
* [Portswigger: Working with JWTs in Burp Suite](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite)
* [Portswigger: Burpsuite JWT Editor extension](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
* [JWT Encoder–Decoder](https://jwt.io/)
* [JWT Attack Methodology](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
* [The JSON Web Token Toolkit v2](https://github.com/ticarpi/jwt_tool)
* [PayloadsAllTheThings/JSON Web Token](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)
* [Attacking JWT authentication - Sjoerd Langkemper](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Attacking%20JWT%20authentication%20-%20Sjoerd%20Langkemper.pdf)
* [Hacking JSON Web Token (JWT) - Rudra Pratap](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Hacking%20JSON%20Web%20Token%20(JWT)%20-%20Rudra%20Pratap.pdf)
* [JWT Writeups Bug Bounty HackerOne (Karim Habeeb)](https://nored0x.github.io/penetration%20testing/writeups-Bug-Bounty-hackrone/#jwt)
