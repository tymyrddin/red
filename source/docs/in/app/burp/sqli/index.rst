SQL injection (SQLi)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy SQL injection Labs
   :target: https://portswigger.net/web-security/all-labs#sql-injection

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an
application makes to its database. It generally allows an attacker to view data that they are not normally able to
retrieve.

SQLi is still a significant threat, but its prevalence has evolved thanks to the widespread use of ORMs (Django,
Hibernate, Entity Framework), prepared statements becoming the default in modern frameworks, and security tooling
(SAST/DAST) catching basic SQLi early.

But it is not dead. It still appears in legacy systems (old PHP, ASP.NET apps), APIs with raw SQL queries (e.g.,
poorly coded microservices), "Fast-moving" dev teams skipping security reviews, admin panels & internal tools (often
neglected in security testing).

It is worth testing for SQLi because of the high impact when found as it can lead to full database takeover, RCE (e.g.,
via `xp_cmdshell` in MSSQL), and authentication bypasses. Also, new attack vectors have emerged. NoSQLi (MongoDB,
CouchDB) is rising, but classic SQLi still exists, and the appearance of second-order SQLi (stored payloads triggering
later).

Prioritise after XSS/SSRF, but before XXE/SSTI.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test for it in legacy apps, APIs with raw SQL, and login/search functions:

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

