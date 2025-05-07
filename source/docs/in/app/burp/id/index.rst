Information disclosure
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Information disclosure Labs
   :target: https://portswigger.net/web-security/all-labs#information-disclosure

Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive
information to its users. Depending on the context, websites may leak all kinds of information to a potential attacker,
including: Data about other users, such as usernames or financial information, Sensitive commercial or business data,
and technical details about the website and its infrastructure.

The dangers of leaking sensitive user or business data are fairly obvious, but disclosing technical information can
sometimes be just as serious. Although some of this information will be of limited use, it can potentially be a
starting point for exposing an additional attack surface, which may contain other interesting vulnerabilities. The
knowledge that you are able to gather could even provide the missing piece of the puzzle when trying to construct
complex, high-severity attacks. For example, database credentials → SQLi/RCE, API keys → Account hijacking, and
Version info → 0-day exploits.

Occasionally, sensitive information might be carelessly leaked to users who are simply browsing the website in a
normal fashion. More commonly, however, an attacker needs to elicit the information disclosure by interacting with the
website in unexpected or malicious ways. They will then carefully study the website's responses to try and identify
interesting behaviour.

Information disclosure remains one of the most frequent web vulnerabilities. While often overlooked, it’s a gateway
for severe exploits like data breaches, account takeovers, and system compromises.

It is worth testing for because misconfigurations and debugging remnants are everywhere. It is low effort, high impact.
Finding exposed data is often trivial, but consequences can be critical (leaked API keys, user PII).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Never a waste of time—it’s the easiest way to find low-hanging fruit that leads to bigger exploits:

   1.md
   2.md
   3.md
   4.md
   5.md
