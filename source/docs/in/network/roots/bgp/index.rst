Border Gateway Protocol (BGP and MP-BGP)
=========================================

Beneath the surface of the internet lies a vast, ancient root system: the Border Gateway Protocol (BGP). It is
the global postal service for digital traffic, the mapmaker that guides your data across the independent networks
that make up the web.

When your request leaves your local network and journeys across the world, BGP takes over. But it is not
searching for the shortest path; it's navigating a complex world of handshake deals and business relationships,
finding the most acceptable route. Each network announces to its neighbours, "I know how to reach these destinations,"
and trust is extended based on private agreements.

This critical system, which also charts the vast new frontiers of IPv6, was built on a foundation of trust, not
strong security. This inherent vulnerability means a simple misconfiguration or malicious lie can cause entire
continents of data to briefly flow down the wrong path, hijacked. Whilst digital guards like RPKI are now
standing watch, the silent, relentless work of BGP remains a testament to both co-operation and fragility.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A global routing system built on trust, making it vulnerable to hijacking and misdirection.

   bgp.md
   mp-bgp.md
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
   ai-powered-bgp-attacks.md
