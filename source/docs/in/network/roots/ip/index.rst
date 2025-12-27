Internet Protocol (IPv4 and IPv6)
=========================================

The Internet Protocol (IP) serves as the fundamental communication backbone of global networks, enabling the
interconnected digital world we rely on today. This guide provides a comprehensive examination of both IPv4 and
IPv6 protocols, their inherent vulnerabilities, and the sophisticated attack vectors that threaten modern network
infrastructure.

As organisations continue their transition from IPv4 to IPv6 whilst often maintaining dual-stack environments,
understanding the security implications of both protocols becomes increasingly critical. The expanded address space
and new features of IPv6 introduce both opportunities and challenges, whilst legacy IPv4 networks continue to face
evolving threats.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: The internet runs on IP. So do attackers.

   ipv4.md
   ipv6.md
   tree.md
   fragmentation.md
   icmp-abuse.md
   arp-spoofing.md
   nat-abuse.md
   slaac.md
   ndp-exploitation.md
   extension-header-abuse.md
   dual-stack-attacks.md
   spoofing.md
   bgp-hijacking.md
   ttl-expiry-attacks.md
   geolocation-spoofing.md

Disclaimer
-----------------------------------------
An attack tree is structural, not operational. It exists in the comfortable world of pure logic, where things
either work or they don't, gates either open or stay closed, and time is merely a dimension I/you/we draw an arrow along.

It's comprehensive. It has branches for sub-prefix hijacking, exact-prefix hijacking, squatting attacks, path
manipulation, and several dozen other variations. Each node connects logically to its children. The structure is clean.

Until someone takes a tree seriously enough to ask `but what would this actually *look* like? <https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/>`_
