Border Gateway Protocol (BGP and MP-BGP)
=========================================

Protocol reference material for BGP and MP-BGP, covering session types, path selection, address families, and
terminology, lives in the Grimoire. This section contains attack trees only.

Beneath the surface of the internet, the Border Gateway Protocol (BGP) maps which networks can reach which
others and by which path. The routing decisions it produces follow not the shortest path but the most acceptable
one: a calculation over peering agreements, commercial relationships, and policy preferences, applied at every
autonomous system boundary on the way to the destination.

Each network announces to its neighbours which destinations it can reach. Those announcements are accepted on
trust, extended based on private agreements rather than verified against any cryptographic proof. A misconfiguration
or a deliberate lie propagates through that trust network with the same authority as a legitimate announcement.
RPKI provides a mechanism for route origin validation, but deployment is incomplete and uneven. The system
functions because most participants behave, and degrades when they do not.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A global routing system built on trust, making it vulnerable to hijacking and misdirection.

   strategic-framing.md
   tree.md
   prefix-hijack.md
   path-manipulation.md
   infrastructure-attacks.md
   mpls-attacks.md
   address-family-exploitation.md
   mp-bgp-session-attacks.md
   rpki-Infrastructure-attacks.md
   ddos-amplification.md
   crypto-attacks.md
   bgp-dns-Infrastructure-attacks.md
   bgp-cdn-cloud-Infrastructure-attacks.md

