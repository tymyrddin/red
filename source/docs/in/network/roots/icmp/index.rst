Internet Control Message Protocol (ICMP)
============================================

The Internet Control Message Protocol (ICMP), often perceived as a simple network utility for diagnostics and error
reporting, presents a surprisingly vast and complex attack surface. Its ubiquitous presence and generally permissive
nature through network defences make it an ideal vehicle for a spectrum of offensive operations.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A hierarchical blueprint for weaponising the ICMP protocol to conduct stealthy reconnaissance, establish covert channels, execute disruptive attacks, and evade security controls across modern networks.

   tree.md
   echo-sweeping.md
   ttl-manipulation-os-fingerprinting.md
   icmp-based-service-discovery.md
   tunelling.md
   fragmented-icmp-exfil-techniques.md
   dns-over-icmp-c2.md
   flood-attacks.md
   amplification-attacks.md
   ping-o-death.md
   nat-firewall-bypass-techniques.md
   lateral-movement-via-icmp.md
   route-advertisement-spoofing.md
   side-channel-attacks.md
   iot-ot-device-crashes.md
   cloud-metadata-service-abuse.md
   adaptive-evasion-techniques.md
   autonomous-attack-systems.md
   forensic-evasion-techniques.md
   security-control-bypass-techniques.md

Disclaimer
-----------------------------------------
An attack tree is structural, not operational. It exists in the comfortable world of pure logic, where things
either work or they don't, gates either open or stay closed, and time is merely a dimension I/you/we draw an arrow along.

It's comprehensive. It has branches for sub-prefix hijacking, exact-prefix hijacking, squatting attacks, path
manipulation, and several dozen other variations. Each node connects logically to its children. The structure is clean.

Until someone takes a tree seriously enough to ask `but what would this actually *look* like? <https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/>`_
