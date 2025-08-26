Internet Protocol Security (IPsec)
===========================================

IPsec is a suite of protocols designed to secure Internet Protocol (IP) communications by authenticating and
encrypting each IP packet in a data stream. It operates at the network layer, providing security for both
IPv4 and IPv6, and is widely used in VPNs, site-to-site tunnels, and secure communication channels. However,
its complexity, cryptographic dependencies, and integration with network stack fundamentals make it a prime
target for exploitation.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Compromising IPsec's cryptographic foundations to breach VPNs and network-layer security:

   ipsec.md
   ipsec-tree.md
   cryptographic-attacks.md
   key-mgmnt-attacks.md
   implementation-flaws.md
   protocol-downgrade-attacks.md
   sa-manipulation-attacks.md
   identity-spoofing.md
   memory-corruption-attacks.md
   resource-exhaustion-attacks.md
   configuration-bypass-attacks.md

