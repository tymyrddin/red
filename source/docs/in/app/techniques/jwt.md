# JSON web tokens attacks

JSON Web Tokens (JWT) are one of the most frequently used methods to exchange information with REST APIs. JSON Web
Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting
information between parties as a JSON object. And it is also frequently misconfigured and abused.

## Steps

* Find JWT tokens
* Identify a test page: Find a request of a page with JWT token which gives a clear response. Profile pages are a good
  start.
* Check for test cases on the page:
    * Check if the same token still works (it may have expired)
    * Algorithm manipulation: Using None as the algorithm; or using symmetric encryption (HMAC) instead of asymmetric
      RSA.
    * Lack of signature validation.
    * Bruteforcing weak secret keys.
    * Secret keys leaking through another attack (like [directory traversal](traversal.md), [XXE](xxe.md),
      or [SSRF](ssrf.md)).
    * Key ID (KID) manipulation: [Directory traversals](traversal.md); [SQL injections](sqli.md);
      and [Command injections](rce.md).
    * `JKU/JWK/x5u/x5c` headers used sending rogue keys.
    * Information leaks in JWT when developers mistake base64 encoding for encrypting.

## Finding JWT tokens

Use Regex to search in proxy history:

```
"[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*"
"[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*"
```

## Escalation

The impact of JWT attacks is usually severe. If an attacker is able to create their own valid tokens with arbitrary
values, they may be able to escalate their own privileges or impersonate other users, taking full control of their
accounts.

## Variants

The bypasses follow the verification flaw: an unverified or only-when-present signature, a
weak signing key recovered by brute force, attacker-supplied keys injected through the `jwk`,
`jku`, or `kid` headers (the last also a path-traversal or injection probe), and algorithm
confusion that signs an HS256 token with the server's RSA public key, with or without that key
exposed. The [JWT attacks runbook](../runbooks/jwt.md) works through each in turn.

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

## Counter moves

JSON web tokens attacks is the case here. These come back to the same answers: validated input, encoded output,
server-side authorisation, and patched dependencies. Defenders' notes on this are
under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
