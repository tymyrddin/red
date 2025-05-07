Server-side template injection (SSTI)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Server-side template injection Labs
   :target: https://portswigger.net/web-security/all-labs#server-side-template-injection

Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side
template injection attacks can occur when user input is concatenated directly into a template, rather than passed in
as data. This allows attackers to inject arbitrary template directives in order to manipulate the template engine,
often enabling them to take complete control of the server. As the name suggests, server-side template injection
payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical
client-side template injection.

SSTI is less common than vulnerabilities like SQLi or XSS, but it remains a high-impact issue when found. Its prevalence
depends on the tech stack.

It is most common in Python (Jinja2, Django templates), Java (Thymeleaf, Freemarker), JavaScript (Node.js with EJS, Pug),
Ruby (ERB, Slim), and PHP (Twig, Smarty).

It is less common in modern frameworks with auto-escaping (e.g., React, Angular) and static sites or apps without
dynamic templating. Still worth testing for, but focus after more common vulns (SQLi, XSS, CSRF).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test for it where templating is used:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md