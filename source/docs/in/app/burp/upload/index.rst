File upload vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy XML external entity File Upload Labs
   :target: https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities

In almost every web application there is functionality for uploading files. This file may be in form of text, video,
image, etc. Developers often forget Content-Type vs. file extension checks, malicious files disguised as images
(e.g., shell.jpg.php), parser inconsistencies (e.g., Apache’s mod_mime quirks), and cloud impact: Uploads to S3/Blob
Storage can lead to bucket hijacking.

File upload vulnerabilities remain extremely common and are frequently exploited in real-world attacks. They appear in
web applications (social media, forums, CMS platforms), Enterprise systems (HR portals, document management), APIs &
cloud services (user avatars, PDF generators).

Test for them because upload flaws can be chained with RCE (uploading `.php`, `.jsp`, `.aspx` shells), XSS (malicious
SVG/HTML files), and SSRF (via PDF generators and Office docs).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Far from a waste of time—file upload vulnerabilities are low-hanging fruit with high impact. Test aggressively, especially in apps handling sensitive data:

   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md