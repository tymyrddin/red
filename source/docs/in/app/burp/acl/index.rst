Access control vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Access control vulnerabilities Labs
   :target: https://portswigger.net/web-security/all-labs#access-control-vulnerabilities

Access control (or authorisation) is the application of constraints on whom (or what) can perform attempted actions
or access resources that they have requested. In the context of web applications, access control is dependent on
authentication and session management.

Broken access controls are a commonly encountered and often critical security vulnerability. Design and management
of access controls is a complex and dynamic problem that applies business, organisational, and legal constraints to
a technical implementation. Access control design decisions have to be made by humans, not technology, and the
potential for errors is high.

These are consistently a top OWASP risk and still common because apps with roles (Admin/User/Moderator) often
misconfigure checks, APIs & microservices have poorly enforced policies in distributed systems, and for the rest due
to custom logic flaws (We assumed ...).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test every endpoint—IDOR is low-hanging fruit:

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
