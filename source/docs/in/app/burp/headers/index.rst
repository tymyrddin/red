HTTP Host header attacks
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy HTTP Host header attacks Labs
   :target: https:portswigger.net/web-security/all-labs#http-host-header-attacks

The purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with.
If requests didn't contain `Host` headers, or if the Host header was malformed in some way, this could lead to issues
when routing incoming requests to the intended application.

Historically, this ambiguity didn't exist because each IP address would only host content for a single domain.
Nowadays, largely due to the ever-growing trend for cloud-based solutions and outsourcing much of the related
architecture, it is common for multiple websites and applications to be accessible at the same IP address. This
approach also increased in popularity partly as a result of IPv4 address exhaustion.

Host header attacks remain a persistent threat, especially in web applications using virtual hosting or proxying).
While not as widespread as XSS or SQLi, they’re high-risk when exploited, leading to password reset poisoning,
cache poisoning, and SSRFinternal service access.

It is worth testing for when the app relies on the `Host` header for generating linksemails (e.g., password resets),
multi-tenant setups (shared hosting), routing traffic (reverse proxies, CDNs), and if you see behaviour changes when
tampering with `Host`.


.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Not a waste of time—test if the app uses `Host` for logic:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
