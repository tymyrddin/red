Internet Protocol (IPv4 and IPv6)
=========================================

These attack trees cover IP as an attack surface rather than a protocol specification. IPv4 and IPv6 carry distinct failure modes: fragmentation abuse, source spoofing, header manipulation, dual-stack trust confusion, and neighbour discovery exploitation. Each is modelled here as a path toward routing manipulation or trust collapse. Protocol reference material for IPv4 and IPv6, covering addressing notation, subnetting, and address types, lives in the Grimoire.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The internet runs on IP. So do attackers.

   tree.md
   fragmentation.md
   arp-spoofing.md
   nat-abuse.md
   slaac.md
   ndp-exploitation.md
   extension-header-abuse.md
   dual-stack-attacks.md
   spoofing.md
   bgp-hijacking.md
   ttl-expiry-attacks.md
