# Layer 2 attacks

Layer 2 is the Ethernet and switching layer, responsible for delivering frames between directly connected hosts using MAC addresses. Because it sits below IP, attacks at this layer affect all protocols running above it simultaneously. A host whose ARP cache has been poisoned will send all its traffic through the attacker regardless of whether the target application uses TLS, because the routing decision that sends the packet to the wrong MAC address happens before encryption.

Layer 2 attacks are most relevant inside an already-accessed network segment. They are the primary technique for escalating from a foothold on one host to man-in-the-middle positioning across an entire subnet, or for accessing VLANs beyond the initially compromised segment.

## ARP poisoning

ARP is unauthenticated by design: any host can send a gratuitous ARP reply claiming any IP address maps to any MAC address. Targets that receive these replies update their ARP caches accordingly, and subsequent traffic to the claimed IP address is sent to the attacker's MAC instead.

`arpspoof` and `bettercap` automate this at the subnet scale. The attacker poisons both the victim and the default gateway, positioning themselves between the two. With IP forwarding enabled, traffic flows through the attacker transparently.

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Poison victim -> gateway and gateway -> victim
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
arpspoof -i eth0 -t 192.168.1.1 192.168.1.10
```

In this position, the attacker can capture credentials from unencrypted protocols, attempt TLS stripping against HTTP traffic, and inject content into unencrypted sessions. For protocols that cannot be stripped, having traffic flow through the attacker still provides timing data and connection metadata.

## STP root bridge attacks

The Spanning Tree Protocol prevents loops in switched networks by electing a root bridge and blocking redundant links. The election is based on the bridge priority value: the switch with the lowest priority becomes root. An attacker connected to the network can send STP BPDUs with a lower priority than the current root, causing switches to elect the attacker's machine as the new root bridge and reroute traffic through it.

```bash
yersinia -G  # Graphical interface
# Or via CLI
yersinia stp -attack 4  # Send conf BPDU with priority 0
```

STP attacks are more disruptive than ARP poisoning and carry a risk of creating network instability if not managed carefully. They are most useful in environments where multiple VLANs need to be targeted simultaneously, since STP root bridge position affects all VLANs using the default configuration.

## VLAN hopping

VLANs are a logical segmentation mechanism, but the 802.1Q implementation has two attack surfaces.

Switch spoofing works when a switch port is configured in `dynamic desirable` or `dynamic auto` trunk negotiation mode. An attacker can respond to DTP negotiation frames and cause the switch to form a trunk, which delivers traffic from all VLANs rather than a single access VLAN.

Double tagging exploits the way some switches handle 802.1Q tags. An attacker on VLAN 10 crafts a frame with two 802.1Q tags: an outer tag matching the native VLAN (typically VLAN 1) and an inner tag for the target VLAN. When the first switch strips the native VLAN tag and forwards the frame, the second switch sees only the inner tag and delivers the frame to the target VLAN. This attack is unidirectional, delivering traffic to the target VLAN but not returning responses to the attacker.

```bash
# VLAN hopping with scapy (double tagging)
from scapy.all import *
pkt = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=20)/IP(dst="10.20.0.1")/ICMP()
sendp(pkt, iface="eth0")
```

Proper defence requires explicitly configuring all non-trunk ports as access ports and setting the native VLAN to an unused VLAN ID rather than VLAN 1.
