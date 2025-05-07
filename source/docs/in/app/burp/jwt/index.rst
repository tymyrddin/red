JSON web tokens (JWT) vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy JWT Labs
   :target: https://portswigger.net/web-security/all-labs#jwt

JSON web tokens (JWTs) are a standardised format for sending cryptographically signed JSON data between systems. They
can theoretically contain any kind of data, but are most commonly used to send information ("claims") about users
as part of authentication, session handling, and access control mechanisms.

JWTs are a popular choice for highly distributed websites where users need to interact seamlessly with multiple
back-end servers.

Design issues and flawed handling of JSON web tokens (JWTs) can leave websites vulnerable to a variety of
high-severity attacks. As JWTs are most commonly used in authentication, session management, and access control
mechanisms, these vulnerabilities can potentially compromise the entire website and its users.

JWT vulnerabilities remain prevalent, affecting ~25-40% of modern web apps (APIs, microservices, SPAs).
While frameworks have improved, misconfigurations and developer mistakes keep JWTs a prime target.

These vulnerabilities persist because developers misuse libraries (e.g., disabling signature checks), weak secrets are
used (Hardcoded or guessable HS256 keys), algorithm confusion (accepting unsigned tokens (none alg) or mixing
RS256/HS256), and poor token handling (storing tokens in localStorage (XSS risk) or failing to invalidate them).

It is worth testing for because these vulnerabilities can lead to account takeover (ATO), privilege escalation, token
sidejacking (stolen via XSS or MITM), and API abuse. Plus, their abundance. They are common in APIs/SPAs and used in
70%+ of modern auth systems.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A must-test vulnerability—JWT flaws are low-hanging fruit:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
   8.md
