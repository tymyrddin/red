Cross Site Scripting (XSS)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy XSS Labs
   :target: https://portswigger.net/web-security/all-labs#cross-site-scripting

An XSS vulnerability occurs when attackers can execute custom scripts on a victim’s browser. If an application fails
to distinguish between user input and the legitimate code that makes up a web page, attackers can inject their own
code into pages viewed by other users. The victim’s browser will then execute the malicious script, which might
steal cookies, leak personal information, change site contents, or redirect the user to a malicious site. These
malicious scripts are often JavaScript code but can also be HTML, Flash, VBScript, or anything written in a language
that the browser can execute.

XSS is one of the most common web vulnerabilities, appearing in ~60-70% of applications (based on bug bounty reports
and pentests). It can still be found everywhere because modern SPAs (React, Angular) introduce new XSS vectors
(e.g., `innerHTML`, `dangerouslySetInnerHTML`), vulnerable JS dependencies (e.g., outdated jQuery) in third-party code,
because DOM-Based XSS is hard to detect with static scanners and widespread misconfigurations (e.g. Poor CSP rules
and lack of output encoding.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Absolutely worth testing for because it is easy to find and can lead to CSRF and account takeover exploits:

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
   23.md
   24.md
   25.md
   26.md
   27.md
   28.md
   29.md
   30.md
