OAuth authentication vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy OAuth authentication Labs
   :target: https://portswigger.net/web-security/all-labs#oauth-authentication

The basic OAuth process is widely used to integrate third-party functionality that requires access to certain data
from a user's account. For example, an application might use OAuth to request access to your email contacts list
so that it can suggest people to connect with. However, the same mechanism is also used to provide third-party
authentication services, allowing users to log in with an account that they have with a different website.

OAuth vulnerabilities are increasingly common due to its widespread adoption (~60% of apps use OAuth).
Misconfigurations appear in ~20-30% of implementations, making them a top 5 web security risk (OWASP API Top 10).

They persist because OAuth 2.0’s flexibility leads to misconfigurations (e.g., improper scopes, redirect URIs) and
such poor documentation that developers often copy-paste and adapt insecure examples. Phishing & social engineering
allow attackers to exploit consent screens and token leaks.

It is worth testing for because it can lead to account takeover (ATO), data breaches, and privilege escalation and it
is common in SaaS/Cloud Apps (Google, Facebook, Microsoft logins).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Critical to test—OAuth is a goldmine:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
