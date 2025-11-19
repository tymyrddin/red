Field notes from the fragrant branches of web app exploitation
===============================================================

Beneath the delicate canopy of web applications, where blossoms of functionality unfurl in the digital breeze, lurk
vulnerabilities as pervasive as pests in an orchard. Each petal-perfect endpoint, whether a login form, search bar, or
API gateway, offers more than just nectar to legitimate users; it extends an invitation to every crawling, burrowing,
and flying exploit in the ecosystem. Cross-site scripting (XSS) flits like aphids between leaves, injecting malicious
scripts where pollen should be. SQL injection bores like a worm into the fruit’s core, while CSRF and clickjacking
weave invisible threads to redirect and trap unsuspecting visitors. Even the sturdiest branches, authentication and
access control, crumble under the weight of IDOR beetles or SSRF moths tunneling through their bark.

To navigate this orchard is to understand its hidden rot. Race conditions split ripe fruit mid-air; XXE injections
gnaw at the roots of data parsing; prototype pollution taints the genetic code of JavaScript itself. From web cache
poisoning’s spoiled nectar to HTTP smuggling’s contorted vines, each vulnerability reveals how fragile the ecosystem
truly is. These notes dissect PortSwigger’s grafted challenges and Root-me’s wild thickets, exposing how file uploads
become backdoored blossoms, how JWT attacks mimic stolen pollen, and how a single RCE can turn the whole canopy into
a hacker’s harvest.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A garden’s beauty won't stop weevils:

   xss.md
   redirects.md
   clickjacking.md
   csrf.md
   idor.md
   sqli.md
   race.md
   ssrf.md
   id.md
   xxe.md
   cache.md
   smuggling.md
   ssti.md
   traversal.md
   auth.md
   sso.md
   acl.md
   business.md
   headers.md
   sockets.md
   rce.md
   sop.md
   disclosure.md
   shells.md
   jwt.md
   pollution.md