Cross-origin resource sharing (CORS) misconfigurations
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy CORS Labs
   :target: https://portswigger.net/web-security/all-labs#cross-origin-resource-sharing-cors

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located
outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP).

The vulnerabilities can be found in APIs, SPAs, and cloud services.

It persists because developers often misconfigure Access-Control-Allow-Origin (e.g., wildcards * with credentials), and
complex architectures (microservices, CDNs) introduce edge-case flaws.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Not a waste of time, misconfigs are common and dangerous:

   1.md
   2.md
   3.md
   4.md
