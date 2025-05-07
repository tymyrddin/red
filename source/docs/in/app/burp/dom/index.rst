DOM-based vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy DOM-based vulnerabilities Labs
   :target: https://portswigger.net/web-security/all-labs#dom-based-vulnerabilities

DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value, known
as a source, and passes it into a dangerous function, known as a sink.

DOM-based vulnerabilities are increasingly prevalent, affecting ~30-50% of modern JavaScript-heavy applications
(SPAs, PWAs, and dynamic websites). As web apps rely more on client-side rendering, these flaws are becoming a
top-5 frontend security risk.

Testing for it is well worth it because these vulenerabilities can lead to XSS, CSRF, and client-side data theft and
often bypass traditional WAFs/server-side protections. Not to mention the growing attack surface. Increasingly, apps use
frameworks like React, Vue, and Angular, which introduce new DOM manipulation risks.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Never skip DOM testing in JS-heavy apps:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
