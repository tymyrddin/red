Directory traversal (also known as file path traversal)
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Directory Traversal Labs
   :target: https://portswigger.net/web-security/all-labs#directory-traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read
arbitrary files on the server that is running an application. This might include application code and data, credentials
for back-end systems, and sensitive operating system files.

In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application
data or behaviour, and ultimately take full control of the server.

It remains a fairly common vulnerability, especially in legacy systems, misconfigured servers and in APIs &
file-handling functions. Directory Traversal still appears in real-world applications, though less frequently than
SQLi or XSS. Testing for it is not a waste of time, but focus on high-risk areas first.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Directory Traversal can on oaccasion still be a relevant threat in file-processing apps, APIs, and older systems:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
