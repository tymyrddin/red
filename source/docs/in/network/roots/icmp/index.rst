Internet Control Message Protocol (ICMP)
============================================

The Internet Control Message Protocol (ICMP) is a diagnostic and error-reporting mechanism that most network
defences treat as routine. Its ubiquity and the permissive posture most devices and firewalls extend to it can
make it a reliable vehicle for reconnaissance, covert channels, amplification, and lateral movement, without
announcing itself as anything other than normal traffic.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: A ubiquitous diagnostic protocol pressed into service for reconnaissance, covert channels, and disruption.

   tree.md
   echo-sweeping.md
   ttl-manipulation-os-fingerprinting.md
   icmp-based-service-discovery.md
   tunelling.md
   fragmented-icmp-exfil-techniques.md
   dns-over-icmp-c2.md
   flood-attacks.md
   amplification-attacks.md
   nat-firewall-bypass-techniques.md
   lateral-movement-via-icmp.md
   route-advertisement-spoofing.md
   iot-ot-device-crashes.md
   cloud-metadata-service-abuse.md
