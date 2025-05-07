Authentication vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Authentication Labs
   :target: https://portswigger.net/web-security/all-labs#authentication

The majority of threats related to the authentication process are associated with passwords and password-based
authentication methods. Broken authentication also causes a significant amount of vulnerabilities.

As well as potentially allowing attackers direct access to sensitive data and functionality, they also expose
additional attack surface for further exploits.

These are declining due to MFA, but are still critical and persist due to weak default credentials in IoT devices,
password recovery flaws where resets are sent to unverified emails/phones, and brute-forceable logins with a
lack of rate-limiting.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Always check OAuth/SSO integrations—they’re a goldmine for flaws:

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
