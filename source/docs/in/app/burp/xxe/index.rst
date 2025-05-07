XML external entity attacks (XXEs)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy XML external entity (XXE) injection Labs
   :target: https://portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection

XML external entity attacks (XXEs) are fascinating vulnerabilities that target the XML parsers of an application.

XXE is less common (~10-15% of apps) but extremely dangerous when present. You can find it in legacy APIs (SOAP,
XML-RPC), PDF generators, Office docs (e.g., SVG/XML parsing), and misconfigured cloud services (AWS S3, Azure Blob).

Testing for it is worth it for systems processing XML (e.g., finance, healthcare) because it can lead to SSRF, RCE,
or data leaks (e.g., `/etc/passwd`).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test in XML-heavy apps (APIs, file processors), but skip if no XML is used:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
   8.md
   9.md
