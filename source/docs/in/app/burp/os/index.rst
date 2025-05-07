OS command injection alias shell injection
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy OS command injection Labs
   :target: https://portswigger.net/web-security/all-labs#os-command-injection

OS command injection (also known as shell injection) is a web security vulnerability that allows an attacker to execute
arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise
the application and all its data.

OS command injection remains a critical risk, though much less common than SQLi or XSS. It can lead to full server
compromise (RCE), and persists in legacy systems (old admin panels, IoT devices), DevOps tools (CI/CD pipelines,
backup scripts), and APIs calling shell commands (e.g., ping, curl).

It still exists because developers still use `system()`, `exec()`, or `os.popen()` with raw user input, and containers,
microservices, and third-party libraries introduce new attack surfaces.

It is worth testing for when the app executes shell commands (e.g., file conversions, system checks), you find user
input passed to CLI tools (e.g., ping 8.8.8.8; rm -rf /), and internal/admin tools are used (these often lack security
reviews).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Prioritize testing in admin interfaces, DevOps/automation tools, apps calling shell commands:

   1.md
   2.md
   3.md
   4.md
   5.md
