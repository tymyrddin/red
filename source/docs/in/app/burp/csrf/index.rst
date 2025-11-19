Cross-site request forgery (CSRF)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy CSRF Labs
   :target: https://portswigger.net/web-security/all-labs#cross-site-request-forgery-csrf

Cross-site request forgery (CSRF) is a client-side technique used to attack other users of a web application.

CSRF remains a persistent but declining threat, but it is still a Top 10 Web Risk (OWASP A05:2021) and appears in
legacy systems (older PHP/Java apps), APIs with cookie-based auth (especially state-changing actions), and
misconfigured SPAs (missing anti-CSRF tokens).

Testing is still worth it when the he app uses session cookies (not just JWT/Bearer tokens), state-changing actions
exist (e.g., password changes, payments), and there are no framework defaults (e.g., Django CSRF middleware disabled).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Not dead yet, test CSRF where cookies meet state changes:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
   8.md
   9.md
   10.md
   11.md
   12.md
