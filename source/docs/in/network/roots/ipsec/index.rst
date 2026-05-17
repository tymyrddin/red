Internet Protocol Security (IPsec)
===========================================

IPsec secures IP communications through authentication and encryption at the network layer, widely deployed
in VPNs and site-to-site tunnels. The surface it presents to an adversary is proportional to its complexity:
key negotiation steps, cryptographic mode selection, identity verification, and implementation variation all
create points where the security model can be degraded, abused, or circumvented rather than broken outright.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Compromising IPsec's cryptographic foundations to breach VPNs and network-layer security:

   ipsec.md
   tree.md
   cryptographic-attacks.md
   key-mgmnt-attacks.md
   implementation-flaws.md
   protocol-downgrade-attacks.md
   sa-manipulation-attacks.md
   identity-spoofing.md
   memory-corruption-attacks.md
   resource-exhaustion-attacks.md
   configuration-bypass-attacks.md
