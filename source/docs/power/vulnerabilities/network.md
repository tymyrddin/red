# Network security assessment

Testing the walls that were supposed to keep attackers out.

The Patrician once observed that Ankh-Morpork's city walls were primarily psychological barriers, their effectiveness depending more on the shared belief that they meant something than on their actual structural integrity. Network segmentation in OT environments often works on precisely the same principle. Everyone agrees that the SCADA network is "isolated" from the business network because there's a firewall between them, and that firewall has rules that someone wrote down once in 2009. Whether those rules actually prevent anything useful is a question nobody particularly wants to answer.

Network security assessment in OT is where the comfortable fictions of network architecture meet the uncomfortable reality of what packets actually do. It's the process of determining whether the network is genuinely divided into security zones or merely into administrative conveniences, whether the firewalls are filtering based on security requirements or based on what seemed annoying to block at the time, and whether your "air-gapped" system is actually air-gapped or just very reluctant to admit it has a Wi-Fi adapter.

The stakes here are somewhat higher than in IT. A VLAN hopping attack that gives you access to the business network might let you steal emails. The same attack on an OT network might let you adjust the recipes for the chemical mixing process. The business network's response would be "my inbox is compromised", the OT network's response might be "my facility is evacuated and there's a rainbow-coloured cloud drifting towards the city".

## The network as it exists versus the network as documented

At UU P&L, the official network diagram showed a beautifully segmented architecture. The SCADA network (VLAN 10) was 
isolated from the historian network (VLAN 20), which was separated from the engineering workstation network (VLAN 30), 
which was distinct from the business network (VLAN 40). Each VLAN had carefully chosen IP ranges. Someone had even 
colour-coded them.

What the diagram didn't show was that all four VLANs were configured on every switch in the facility, with every 
port configured as a trunk port "for flexibility", and that the "firewall" between them was actually just a Linux 
box running iptables with a default policy of ACCEPT that someone had added three years ago "temporarily" while 
troubleshooting a connectivity issue.

Start by determining what the network actually looks like, not what the diagram claims it looks like:

```bash
# Discover actual network topology with LLDP/CDP
sudo nmap -sU -p 161 --script snmp-interfaces 192.168.10.0/24

# Map VLAN configuration
sudo nmap --script broadcast-dhcp-discover

# Identify routing between supposedly separate networks
traceroute -I <target_in_different_segment>
```

Document every route between supposedly isolated segments. These are either legitimate documented crossings (maintenance access, data diodes, etc.) or they're unintentional bridges that nobody wants to talk about but everyone relies upon.

## Network segmentation validation

True network segmentation means that if someone compromises a system in Zone A, they cannot easily move to Zone B. False network segmentation means that Zone A and Zone B are different colours on the network diagram.

The Purdue Model, that lovely hierarchical structure that everyone references in their security policies, assumes that networks are segmented into levels with strict controls between them. Level 0 (field devices) can only talk to Level 1 (controllers), which can only talk to Level 2 (supervisory systems), and so on up to Level 5 (corporate network). In practice, of course, the field device has an embedded web server that the plant manager checks from his laptop on the corporate network, the controller has a direct connection to the engineering workstation for "efficiency", and the supervisory system has a VPN tunnel to the vendor's support centre because that was easier than training local staff.

Test segmentation systematically:

### Verify physical segmentation

If networks are claimed to be on separate physical infrastructure, verify this. At one facility, the "isolated" SCADA network and the business network were on different VLANs but the same physical switches, meaning a single power supply failure would take down both.

### Test VLAN segmentation

VLANs are convenient administrative divisions, not security boundaries. They're like announcing that everyone with surnames A through M must use the north door and everyone with surnames N through Z must use the south door. It's organised, but it's not secure.

Try VLAN hopping attacks with [Yersinia](https://github.com/tomac/yersinia):

```bash
# DTP (Dynamic Trunking Protocol) exploitation
sudo yersinia -G  # GUI mode

# Or command line for switch spoofing
sudo yersinia -I  # Interactive mode
# Select DTP protocol and enable trunking
```

The double-tagging attack is particularly elegant in its simplicity. You send a packet with two VLAN tags. The first switch strips the outer tag (as switches do) and forwards it. The second switch sees what it thinks is a normal tagged packet and forwards it to the target VLAN. It's like writing an address on an envelope, putting that envelope in another envelope with a different address, and relying on the postal service's habit of only checking the outermost envelope.

### Test inter-VLAN routing

Even if VLANs are properly isolated at Layer 2, they're often connected at Layer 3 through routers or Layer 3 switches. Check whether routing between VLANs is appropriately filtered:

```bash
# From one VLAN, try to reach hosts in other VLANs
ping <ip_in_different_vlan>
nmap -Pn -p- <ip_in_different_vlan>

# Check for unexpected routing
ip route show
netstat -rn
```

At UU P&L, the routing table showed that while the SCADA VLAN couldn't route directly to the business network, it 
could route to the engineering VLAN, which could route to the DMZ, which could route to the business network. It was 
a three-hop journey instead of a direct connection, which made everyone feel better even though the security benefit 
was purely psychological.

## Firewall rule analysis

Industrial firewalls often start with good intentions. Someone writes a ruleset based on actual requirements, documents what each rule does, and implements a change control process. Six months later, the ruleset has accumulated exceptions for "temporary" projects, workarounds for systems that "don't work properly" with strict filtering, and rules nobody understands but nobody dares delete because "something might break".

The end result often resembles the Ankh-Morpork legal code, layers upon layers of modifications and exceptions that nobody can fully comprehend but everyone fears changing.

### Document the current ruleset

Before testing firewall effectiveness, understand what rules exist:

```bash
# For accessible network devices
nmap --script firewall-bypass <firewall_ip>

# Test what's actually blocked
nmap -sS -p- <target_behind_firewall>
nmap -sT -p- <target_behind_firewall>  # Different scan type
hping3 -S <target_behind_firewall> -p 80  # Crafted packets
```

### Test for rule shadowing

Rule shadowing occurs when an earlier rule makes a later rule unreachable. Imagine a ruleset that says "block all traffic from 192.168.1.0/24" on line 10 and "allow traffic from 192.168.1.50 on port 443" on line 20. The second rule is shadow, permanently hidden behind the first rule like a short person standing behind a tall person in a photograph.

### Test for protocol filtering bypass

Many OT firewalls filter based on port numbers rather than deep packet inspection. They'll block port 22, confident they've stopped SSH, not realising you can run SSH on port 443 or port 53 or port 80 or any other port that is allowed through.

Test protocol filtering with [Scapy](https://scapy.net/):

```python
from scapy.all import *

# Create packets that look like allowed protocols
# but carry different data
packet = IP(dst="target_ip")/TCP(dport=80)/Raw(load="SSH-2.0-OpenSSH_7.4")
send(packet)

# Test fragment handling
send(fragment(packet))

# Test protocol encapsulation
packet = IP(dst="target_ip")/GRE()/IP(dst="internal_ip")/TCP(dport=22)
send(packet)
```

At UU P&L, the firewall blocked all traffic to the SCADA network except for Modbus TCP (port 502) and HTTP (port 80). 
This seemed secure until we discovered that the embedded devices accepted SSH connections on port 80 if you sent the 
right handshake, at which point the web server would politely step aside and let the SSH daemon take over.

## Protocol filtering effectiveness

OT networks carry protocols that were designed when "security" meant "physical security" and "access control" meant "a lock on the computer room door". These protocols often have no authentication, no encryption, and no validation that commands are coming from legitimate sources.

Modern security devices attempt to filter these protocols, checking that Modbus traffic actually looks like Modbus and that DNP3 packets follow the specification. In practice, these filters are often either too strict (blocking legitimate traffic) or too lenient (allowing obvious attacks).

### Test protocol validation

If the firewall claims to do deep packet inspection of OT protocols, test whether it actually validates them:

```python
# Using Scapy for malformed protocol testing
from scapy.all import *
from scapy.contrib.modbus import *

# Send malformed Modbus packet
malformed = IP(dst="target")/TCP(dport=502)/ModbusADURequest(
    transId=1234,
    unitId=1,
    funcCode=0xFF  # Invalid function code
)
send(malformed)

# Test oversized packets
large = IP(dst="target")/TCP(dport=502)/ModbusADURequest(
    transId=1234,
    unitId=1
)/Raw(load="A"*10000)
send(large)
```

Many OT-aware firewalls will happily pass malformed packets that crash the target device, not because they're malicious but because they assume that if it uses port 502 and has bytes that vaguely resemble Modbus, it must be fine.

## Intrusion detection and prevention system bypass

IDS and IPS systems in OT environments face a difficult challenge. They must detect attacks without generating so many false positives that operators disable them, but they must also avoid false negatives that let real attacks through. The signal-to-noise ratio in OT networks is often terrible, with legitimate operational activities that look suspiciously like attacks.

At UU P&L, the IDS generated an average of 3,000 alerts per day, of which approximately 2,995 were false positives 
caused by normal SCADA operations that the IDS didn't understand. After six months, operators had learned to ignore 
all IDS alerts, at which point the system was providing no security benefit whatsoever but was still consuming 
network bandwidth and computing resources.

### Test signature-based detection

Signature-based IDS/IPS systems look for known attack patterns. They're like security guards who've been given photographs of known criminals, they're very good at catching those specific people but utterly useless against anyone new.

Test evasion with fragmentation:

```python
from scapy.all import *

# Fragment packets to evade signature matching
attack = IP(dst="target")/TCP(dport=502)/"ATTACK_SIGNATURE"
frags = fragment(attack, fragsize=8)
send(frags)
```

### Test timing-based evasion

Many IDS systems look for rapid sequences of suspicious activity. Slow down your reconnaissance enough, and you'll slip under their temporal threshold:

```bash
# Very slow scanning
nmap -T0 -sS <target>

# Add random delays between probes
nmap --scan-delay 10s <target>
```

This is less effective if the IDS correlates events over longer time periods, but many OT IDS systems are configured for short time windows to reduce memory usage and processing requirements.

### Test protocol-specific evasion

OT protocols often have multiple valid ways to express the same command. An IDS signature that looks for "write to address 0x1000" might miss a command that writes to "40001" (the Modbus notation for the same address):

```python
# Multiple encodings of similar commands
modbus_write_coil = IP(dst="target")/TCP(dport=502)/ModbusADURequest(
    funcCode=5,
    registerAddr=0x1000,
    registerValue=0xFF00
)

modbus_write_multiple = IP(dst="target")/TCP(dport=502)/ModbusADURequest(
    funcCode=15,
    registerAddr=0x1000,
    quantityOutput=1,
    byteCount=1,
    outputValue=[0xFF]
)
```

Both commands achieve roughly the same result, but IDS signatures often only catch one variant.

## Wireless security assessment

Wireless networks in OT environments exist in a perpetual state of denial. The security policy says "no wireless networks in OT zones", the network diagram shows no wireless networks, and the site security checklist confirms "no unauthorised wireless access points". Meanwhile, three engineers have deployed Wi-Fi access points "temporarily" for their tablets, the maintenance contractor installed a wireless bridge to avoid running cables, and half the "wired" sensors are actually using wireless backhaul that nobody documented.

At UU P&L, official policy forbade wireless networks in production areas. In reality, there were 17 wireless access 
points within the SCADA zone, of which four were using WEP encryption (which hasn't been secure since approximately 
2001), seven were using WPA2 with the password "password123", three were completely open, two were rogue access points 
from staff personal devices, and one was actually a wireless bridge installed by a contractor who'd left the company 
five years ago and nobody knew how to log into anymore.

### Discover wireless networks

Before you can assess wireless security, you need to know what wireless networks exist:

```bash
# Scan for wireless networks
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon

# Look for hidden SSIDs
sudo airodump-ng -c <channel> --bssid <ap_mac> wlan0mon

# Identify rogue access points by examining MAC OUI
# and comparing to authorised vendors
```

Pay particular attention to access points using OT device manufacturers' default SSIDs or located in places that shouldn't have wireless coverage.

### Test encryption strength

If you find wireless networks (and you will), assess their encryption:

```bash
# Capture handshake for WPA/WPA2
sudo airodump-ng -c <channel> --bssid <ap_mac> -w capture wlan0mon

# Deauth clients to force re-authentication (if authorised)
sudo aireplay-ng -0 5 -a <ap_mac> wlan0mon

# Test password strength offline
aircrack-ng -w /path/to/wordlist capture.cap
```

For WEP (which you shouldn't find, but probably will), the process is even simpler:

```bash
# Capture IVs
sudo airodump-ng -c <channel> --bssid <ap_mac> -w wep wlan0mon

# Generate traffic if network is idle
sudo aireplay-ng -3 -b <ap_mac> wlan0mon

# Crack WEP (usually takes minutes)
aircrack-ng wep.cap
```

Finding WEP in 2024 is like finding someone still using a cylinder lock in a world that's moved on to card access. It's not just outdated, it's actively negligent.

### Test wireless segmentation

Even if wireless encryption is strong, verify that wireless clients can't access systems they shouldn't:

```bash
# Once connected to wireless network
nmap -sn <ot_network_range>
nmap -p- <critical_system>
```

Wireless networks that bridge directly into critical OT segments without additional authentication or filtering are gift-wrapped attack vectors.

## Switch security assessment

Network switches, those humble boxes that everyone takes for granted, are often the weakest link in OT network security. They're assumed to be secure because they're infrastructure rather than endpoints, they're rarely patched because "switches don't get hacked", and they're configured with default settings because "changing switch configuration might break something".

### Test port security

Port security is supposed to limit which MAC addresses can connect to which switch ports. It's like a bouncer checking names against a guest list, except the bouncer is easily confused and the guest list was written in 2008.

```bash
# Test MAC address spoofing
sudo macchanger -m <authorised_mac> eth0
# Then reconnect and test access

# Test MAC flooding
sudo macof -i eth0
# Watch if switch fails open (becomes a hub)
```

MAC flooding attacks overwhelm the switch's MAC address table, causing it to fail open and broadcast all traffic to all ports. Suddenly your switched network becomes a hub, and everyone can see everyone else's traffic. It's like a security guard getting so confused about who's allowed where that they just open all the doors and hope for the best.

### Test VLAN configuration

Switch VLAN configuration is where theory meets implementation, and the results are often disappointing:

```bash
# Use Yersinia for VLAN hopping tests
sudo yersinia -G

# DTP (Dynamic Trunking Protocol) attacks
# VTP (VLAN Trunking Protocol) attacks
# STP (Spanning Tree Protocol) attacks
```

[Yersinia](https://github.com/tomac/yersinia) is specifically designed for Layer 2 attacks. It's named after the bacteria that causes plague, which gives you some idea of how its authors viewed switch security.

### Test Spanning Tree Protocol manipulation

STP prevents loops in switched networks. It's also exploitable if switches accept STP messages from unauthorised sources:

```bash
# Yersinia STP attack
# Claim to be root bridge with high priority
# Potentially cause network topology changes or DoS
```

At UU P&L, we demonstrated that an attacker could send STP messages claiming to be a more authoritative bridge, 
causing the network to reconfigure its topology. All traffic would then route through the attacker's device for 
inspection or modification. The network team insisted this wasn't a real vulnerability because "nobody would think to 
do that". They were less confident after we actually did it.

### Test 802.1X authentication

If the network uses 802.1X for port-based authentication (it probably doesn't, but if it does), test whether it's properly configured:

```bash
# Test for EAP downgrade attacks
sudo eaphammer --interface eth0 --creds

# Test certificate validation
# Connect with self-signed certificate
```

Many 802.1X implementations don't properly validate certificates, allowing attackers to impersonate the authentication server and capture credentials.

## Routing and access control lists

Access Control Lists (ACLs) on routers are the last line of defence for network segmentation, or the first, depending on your perspective. They're lists of rules saying which traffic is allowed and which isn't, implemented on devices that process millions of packets per second and therefore need to make decisions very quickly.

The problem with ACLs in OT environments is that they accumulate like sedimentary rock. Each layer represents some moment in time when someone needed to add an exception, and nobody dares remove old rules because "something might break". The result is often hundreds of rules, many of which contradict each other or are so broad they're meaningless.

### Document ACL structure

If you have access to router configurations:

```bash
# Cisco
show ip access-lists
show run | include access-list

# Juniper  
show configuration firewall
show firewall filter
```

Look for:

* Overly broad permit rules (permit ip any any)
* Rules that permit RFC1918 addresses from external interfaces
* Rules that haven't been hit in years (check hit counts)
* Rules that conflict with earlier rules
* Rules with comments like "temporary" or "delete after testing"

### Test ACL effectiveness

From different network segments, test what traffic actually gets through:

```bash
# TCP connect scan (least evasive)
nmap -sT -p- <target>

# SYN scan (more stealthy)
sudo nmap -sS -p- <target>

# Fragmented packets
sudo nmap -f <target>

# Specific protocol tests
sudo hping3 -S <target> -p 80
sudo hping3 -U <target> -p 161  # UDP
```

### Test for ACL bypass via source routing

Some older routers honour source routing options, allowing attackers to specify the path packets should take:

```python
from scapy.all import *

# Loose source routing
packet = IP(dst="target", options=IPOption_LSRR(
    routers=["intermediate_router", "target"]
))/ICMP()
send(packet)
```

This should be blocked by modern routers, but "should be" and "is" are different things in OT networks.

## Man-in-the-middle testing

If network segmentation, filtering, and access controls are all inadequate, the next question is whether an attacker who's achieved a network position can intercept and modify traffic.

### ARP poisoning

ARP poisoning is the classic man-in-the-middle attack for local networks. You tell the victim that you're the gateway, you tell the gateway that you're the victim, and all traffic flows through you:

```bash
# Using Ettercap
sudo ettercap -T -M arp:remote /<victim_ip>// /<gateway_ip>//

# Or for more control
sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>
sudo arpspoof -i eth0 -t <gateway_ip> <victim_ip>
# Don't forget to enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
```

[Ettercap](https://www.ettercap-project.org/) is a comprehensive suite for MITM attacks with built-in protocol dissectors for many OT protocols.

### DNS spoofing

If you can intercept DNS traffic, you can redirect victims to malicious servers:

```bash
# Using Ettercap with DNS spoofing
# Edit /etc/ettercap/etter.dns
sudo ettercap -T -M arp -P dns_spoof /<victim>// /<gateway>//
```

In OT networks, DNS spoofing can redirect HMI connections to a fake SCADA server or redirect engineering workstations to malicious update servers.

### Protocol-specific MITM

For OT protocols, capture and analyse traffic to understand what can be modified:

```bash
# Capture Modbus traffic
sudo tcpdump -i eth0 -w modbus.pcap 'tcp port 502'

# Analyse with tshark
tshark -r modbus.pcap -T fields -e modbus.func_code -e modbus.data

# Or use Wireshark for detailed analysis
```

At UU P&L, we demonstrated a MITM attack on Modbus traffic between the HMI and PLCs. We intercepted write commands 
and modified register values, causing the HMI to believe it was setting one value while the PLC received a different 
value. The operators watched their screens show normal operations while the physical process did something entirely 
different. It was only noticeable because we'd made the modifications obvious for the demonstration, a sophisticated 
attacker could have made subtle changes that wouldn't be detected until something failed.

## The reality of network security in OT

Network security in OT environments is rarely as robust as documentation suggests. The network diagram shows clean separation between zones, the security policy describes strict access controls, and the compliance checklist is all green. Meanwhile, the actual network is a tangle of legacy connections, emergency bypasses that became permanent, and "temporary" solutions that nobody quite got around to fixing.

This isn't entirely the fault of the people managing these networks. OT networks evolved organically over decades, with each generation of technology added alongside (not replacing) the previous generation. The result is archaeological, layers of network infrastructure where each layer made sense at the time but the overall structure is comprehensible only to historians and the occasional engineer who was there for most of it.

Your assessment should document the gaps between policy and reality, but it should also acknowledge why those gaps exist. The VLAN configuration that allows engineering workstations to access everything might violate the Purdue Model, but it exists because engineers genuinely need access to everything and nobody had time to implement granular RBAC. The wireless access point with the weak password might be technically non-compliant, but it exists because the alternative was a two-week delay in critical maintenance.

Document the risks, certainly. Prioritise them based on actual exploitability and impact. But remember that you're not assessing someone's security homework, you're assessing the security of an environment where people are trying to keep physical processes running safely while simultaneously meeting production targets, compliance requirements, and budget constraints.

The goal isn't perfect security (which doesn't exist). The goal is security that's good enough that an attacker would have to be quite dedicated to penetrate it, while not being so onerous that operators route around it to get their work done. That's the balance that OT security always seeks and rarely achieves, but understanding the network as it actually exists, not as it's documented, is the first step toward achieving it.
