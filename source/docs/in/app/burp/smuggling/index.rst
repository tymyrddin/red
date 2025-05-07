HTTP request smuggling
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy HTTP request smuggling Labs
   :target: https://portswigger.net/web-security/all-labs#http-request-smuggling

HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that
are received from one or more users.

HTTP request smuggling remains a critical threat, especially in modern architectures (reverse proxies, CDNs,
microservices). Its prevalence is moderate but high-impact when exploited. It can lead to bypassing security controls
(WAFs, authentication), hijacking sessions (steal Cookie/Authorization headers), cache poisoning (serving malicious
content to users), and credential theft (via smuggled requests to internal APIs).

It is still relevant because more layers (load balancers, API gateways, WAFs) increase parsing inconsistencies, and many
servers still mishandle Content-Length vs. Transfer-Encoding conflicts and chunked encoding quirks. And, serverless
(AWS Lambda, Cloudflare Workers) introduces new smuggling vectors.

Testing for HTTP Request Smuggling  is worth it if the app uses reverse proxies (Nginx, HAProxy, Cloudflare), you
notice inconsistent behaviour between frontend/backend servers, and/or the system handles sensitive data (auth headers,
APIs, payment flows).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Prioritize testing in apps behind proxies/CDNs and systems with strict security boundaries (e.g., cloud environments):

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
   14.md
   15.md
   16.md
   17.md
   18.md
   19.md
   20.md
   21.md
   22.md
