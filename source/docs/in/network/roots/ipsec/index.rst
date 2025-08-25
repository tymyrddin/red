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

   ipsec-tree.md
   ipsec-cryptographic-attacks.md
   ipsec-key-mgmnt-attacks.md
   ipsec-implementation-flaws.md
   protocol-downgrade-attacks.md
   ipsec-sa-manipulation-attacks.md
   identity-spoofing.md
   memory-corruption-attacks.md
   ipsec-resource-exhaustion-attacks.md

