Insecure deserialisation
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Insecure deserialisation Labs
   :target: https://portswigger.net/web-security/all-labs#insecure-deserialization

Insecure deserialisation is when user-controllable data is deserialised by an app.

Insecure deserialisation remains a high-severity threat, though it’s less common than XSS or SQLi. However,
when exploited, it often leads to remote code execution (RCE), data tampering, or privilege escalation.

It still exists in APIs & microservices (JSON/XML/YAML parsers), legacy systems (Java/C# serialization, Python pickle),
and DevOps Tools (CI/CD pipelines, configuration files).

It is worth testing for it in apps that use Java/C# binary serialization, Python pickle, or PHP `unserialize()`,
process JWT, XML, or YAML from untrusted sources, and apps that handle session cookies or API tokens with custom
encoding.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Test in apps using binary serialisation and APIs parsing XML/YAML/JWT from users:

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
