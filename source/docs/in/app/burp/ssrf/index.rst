Server-side request forgery (SSRF)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Server-side request forgery Labs
   :target: https://portswigger.net/web-security/all-labs#server-side-request-forgery-ssrf

Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce
the server-side application to make requests to an unintended location.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within
the organisation's infrastructure. In other cases, they may be able to force the server to connect to arbitrary
external systems, potentially leaking sensitive data such as authorization credentials.

SSRF remains a significant and underrated threat, consistently appearing in cloud environments (AWS, Azure, GCP
metadata APIs), APIs & webhooks (URL fetching, PDF generators, Slack integrations), Internal service abuse (database
access, Redis, admin panels), and enterprise applications (ERP, CMS, and legacy systems).

SSRF is critical to test for because it can lead to IAM role hijacking, data leaks, or full cloud compromise, blind
SSRF is common: Many apps fetch URLs without showing responses (check via out-of-band tools like Burp Collaborator),
and evolving bypasses such as DNS rebinding, HTTP smuggling, and `gopher://` exploits keep it relevant.

Prioritize after XSS/SQLi, but before niche vulns (SSTI, XXE).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Always test for it in apps that fetch URLs, process files, or interact with APIs:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
