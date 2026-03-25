Field notes from the identity layer
=====================================================

The endpoint is a triangle: the device, the identity it holds, and the cloud it authenticates to. Compromise any
corner and you can reach the other two. These notes follow that triangle, from the surface you enumerate before
touching anything, through the evasion techniques that keep you invisible on the device, to the credential and
session material that carries you into everything the user could reach.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The device is just the keyring:

   recon.md
   edr-evasion.md
   fileless.md
   credentials.md
   browser.md
   mobile.md
   usb-physical.md
