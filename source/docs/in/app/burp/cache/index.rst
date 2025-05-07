Web cache poisoning
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Web cache poisoning Labs
   :target: https://portswigger.net/web-security/all-labs#web-cache-poisoning

Web cache poisoning is an advanced technique whereby an attacker exploits the behaviour of a web server and cache so
that a harmful HTTP response is served to other users.

A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting
vulnerabilities such as XSS, JavaScript injection, open redirection, and so on.

Still found in web apps using CDNs, reverse proxies, or caching layers.

Still a threat due to complex caching systems (misconfigs in Varnish, Cloudflare, Fastly, etc.), attackers using
chained attacks to poison at scale (HTTP Request Smuggling + Cache Poisoning), and unkeyed inputs (Headers like
X-Forwarded-Host can alter cached responses).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test if the app uses caching layers:

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
   13.md
