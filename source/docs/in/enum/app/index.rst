Nosing out rotten fruit
=============================================================

Application scanning is like sending your code through a TSA checkpoint—except the scanners are Burp Suite and ZAP, and the "liquid restrictions" are buffer overflows. Dynamic analysis throws weird inputs at the app to see if it coughs up secrets, while static analysis stares at the code like a disappointed parent asking, "Why is there SQL injection in this function?"

Why? Because latent vulnerabilities are the app’s dirty secrets, and known vulnerabilities are the ones everyone else is already exploiting. Miss one, and your app becomes a free buffet for hackers.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Finding weaknesses before they are plugged:

   README.md
   scanning.md
   database.md
   binaries.md
   automated.md
   api.md