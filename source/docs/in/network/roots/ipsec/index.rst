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

Disclaimer
-----------------------------------------
An attack tree is structural, not operational. It exists in the comfortable world of pure logic, where things
either work or they don't, gates either open or stay closed, and time is merely a dimension I/you/we draw an arrow along.

It's comprehensive. It has branches for sub-prefix hijacking, exact-prefix hijacking, squatting attacks, path
manipulation, and several dozen other variations. Each node connects logically to its children. The structure is clean.

Until someone takes a tree seriously enough to ask `but what would this actually *look* like? <https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/>`_
