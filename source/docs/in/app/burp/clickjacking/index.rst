Clickjacking
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Clickjacking Labs
   :target: https://portswigger.net/web-security/all-labs#clickjacking

Clickjacking attacks rely on visual tricks to get website visitors to click on user interface elements that will
perform actions on another website. The attack is performed by hiding the target website's UI and arranging the
visible UI so that the user is not aware of clicking the target website. Due to this UI arrangement, this kind of
attack is also known as UI redressing or UI redress attack.

The goal of a clickjacking attack is to trick unsuspecting website visitors into actions on another website like
transferring money, purchasing products, downloading malware, give them like on a social network, and so on.

These attacks are declining due to X-Frame-Options/CSP defaults, but persist in legacy apps omitting frame-busting
headers and complex UI flows (e.g., multi-step auth).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Not much chance of finding something useful, but still worth a quick header check in payment systems:

   1.md
   2.md
   3.md
   4.md
   5.md
