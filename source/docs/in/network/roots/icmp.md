# Internet Control Message Protocol (ICMP)

## Attack tree: Exploit ICMP for malicious purposes

```text
1. Reconnaissance & Network Mapping

    1.1 ICMP Echo Sweeping (Ping Sweep)

        OR: Use fping for parallel scans

        OR: Custom low-rate ICMP probes to evade detection

    1.2 TTL Manipulation for OS Fingerprinting

        AND: Send ICMP Echo with varying TTLs

        AND: Analyze TTL decay patterns

    1.3 ICMP-based Service Discovery

        OR: Abuse ICMP Timestamp Requests

        OR: Leverage ICMP Address Mask Requests

2. Data Exfiltration & Covert Channels

    2.1 ICMP Tunneling

        AND: Encode data in ICMP Echo payloads

        AND: Use tools like icmptunnel (IPv6-enabled)

    2.2 Fragmented ICMP Exfiltration

        OR: Exploit IPv6 fragmentation for DPI evasion

        OR: Split payloads across ICMP packets

    2.3 DNS-over-ICMP (C2)

        AND: Encode DNS queries in ICMP Echo

        AND: Use malware like MosaicLoader for callbacks

3. Denial-of-Service (DoS) & Amplification

    3.1 ICMP Floods

        OR: Direct IPv6 ping6 floods

        OR: Spoofed-source ICMPv6 floods

    3.2 ICMP Amplification

        AND: Spoof victim IP in "Packet Too Big" messages

        AND: Reflect traffic via misconfigured cloud hosts

    3.3 Ping of Death (Modern Variants)

        OR: IPv6 jumbo frames targeting IoT kernels

        OR: Malformed ICMPv6 packets crashing routers

4. Evasion & Protocol Abuse

    4.1 NAT/Firewall Bypass

        AND: Use ICMP Echo Replies for C2 callbacks

        AND: Abuse whitelisted ICMP types (PMTUD)

    4.2 Lateral Movement via ICMP

        OR: APT29-style internal C2 channels

        OR: ICMP-based password spraying (APT41)

    4.3 ICMPv6 Router Advertisement Spoofing

        AND: Send rogue RAs to hijack traffic

        AND: Exploit weak IPv6 neighbor discovery

5. Zero-Day & Hardware Exploits

    5.1 ICMP Side-Channel Attacks

        OR: NetSpectre-style timing leaks

        OR: Infer VM placement via ICMP TTL (cloud)

    5.2 IoT/OT Device Crashes

        AND: Send malformed ICMPv6 to embedded devices

        AND: Trigger firmware bugs (CVE-2020-10148)

    5.3 Cloud Metadata Service Abuse

        OR: ICMP-based IMDSv1 queries (AWS)

        OR: ICMP-triggered SSRF in serverless apps
```

## ICMP flood attacks (Bandwidth exhaustion)

Attack Pattern

* Attackers overwhelm targets with massive ICMP Echo Request (Ping) floods, consuming bandwidth and causing outages.
* Often amplified via smurfing (spoofed source IPs to trigger broadcast replies).

Real-World Examples

* 2022: Russian Hacktivists Target Ukrainian ISPs: Used 100+ Gbps ICMP floods to disrupt banking and government sites; Combined with UDP floods for maximum impact.
* 2023: Chinese APT41 "Double Dragon" Attacks: Flooded Taiwanese telecoms with ICMP Type 3 (Destination Unreachable) packets to destabilize networks.

Why It Works

* Many networks fail to rate-limit ICMP at the edge.
* IoT botnets (Mirai variants) easily generate high-volume floods.

Mitigation

* Deploy ICMP rate-limiting on routers/firewalls.
* Block ICMP at the network edge (except essential types like MTU discovery).

## ICMP redirect attacks (Man-in-the-Middle)

Attack Pattern

* Attackers send malicious ICMP Redirect messages to reroute traffic through a malicious gateway.
* Used for session hijacking, credential theft, or malware injection.

Real-World Examples

* 2021: Iranian Hackers Exploit Cisco Routers: Sent ICMP Redirects to reroute VPN traffic through Iranian servers.
* 2023: Lazarus Group Spoofs Financial Traffic: Redirected SWIFT transaction traffic in Southeast Asia using ICMP Type 5 (Redirect).

Why It Works

* Many routers still accept ICMP Redirects by default.
* Lack of hop-by-hop encryption (e.g., IPsec) in some networks.

Mitigation

* Disable ICMP Redirects on all routers (no ip redirects in Cisco IOS).
* Use encrypted tunnels (IPsec/WireGuard) for sensitive traffic.

## ICMP tunneling (Data exfiltration & C2)

Attack Pattern

* Attackers embed malicious payloads in ICMP packets to bypass firewalls.
* Used for data theft, malware C2, or DNS tunneling evasion.

Real-World Examples

* 2022: Russian GRU "Sandworm" Exfiltrates Data: Used ICMP Echo Reply packets to smuggle stolen documents from Ukrainian agencies.
* 2024: Ransomware Gang Evades Detection: Hid C2 traffic in ICMP Timestamp requests to avoid signature-based IDS.

Why It Works

* Many security tools ignore ICMP payloads as "benign."
* Hard to distinguish from legitimate pings.

Mitigation

* Deep Packet Inspection (DPI) to detect abnormal ICMP payloads.
* Block non-essential ICMP types (e.g., Timestamp, Address Mask).

## Ping of Death (Fragmentation exploits)

Attack Pattern

* Attackers send malformed, oversized ICMP packets to crash systems.
* Modern variants exploit IPv6 fragmentation or kernel bugs.

Real-World Examples

* 2023: Linux Kernel Panic (CVE-2023-0386): A Mirai-variant botnet exploited fragmented ICMPv6 packets to crash IoT devices.
* 2024: Windows TCP/IP Stack DoS (CVE-2024-21306): Attackers triggered BSODs using jumbo ICMP Echo Requests.

Why It Works

* Some devices still mishandle packet reassembly.
* Legacy systems lack patches.

Mitigation

* Patch OS/kernel vulnerabilities promptly.
* Filter oversized ICMP packets at firewalls.

## ICMP NDP attacks (IPv6 exploitation)

Attack Pattern

* Abuse ICMPv6 Neighbor Discovery Protocol (NDP) to poison IPv6 caches.
* Enables MITM, DoS, or SLAAC spoofing.

Real-World Examples

* 2023: "RA-Guard Bypass" in Enterprise Networks: Attackers forged Router Advertisement (RA) packets to hijack IPv6 traffic.
* 2024: Cloud Provider Hijacked via NDP Spoofing: Hackers rerouted AWS EC2 traffic by poisoning Neighbor Caches.

Why It Works

* Many networks lack IPv6-specific protections.
* NDP is stateless and trust-based.

Mitigation

* Enable RA Guard on switches.
* Deploy SEND (Secure Neighbor Discovery) where possible.

## Trends & takeaways

* State-Sponsored Groups Love ICMP – Russian, Chinese, and Iranian APTs abuse it for stealth.
* IPv6 Attacks Are Rising – NDP spoofing is the new ARP poisoning.
* Legacy Threats Persist – Ping of Death still works on unpatched systems.
* Evasion-Focused Techniques – Tunneling and fragmentation bypass modern defences.

## Defence recommendations

For Network Operators

* Rate-limit ICMP (e.g., ≤ 1k pps per source).
* Block non-essential ICMP types (e.g., Redirects, Timestamps).
* Patch firmware for IPv6 NDP vulnerabilities.

For Enterprises

* Monitor ICMP payloads for exfiltration (e.g., Darktrace/Vectra).
* Disable ICMPv6 NDP where unused.

For Cloud Providers

* Filter oversized/fragmented ICMP in hypervisors.
* Enforce IPv6 SEND policies.

## Thoughts

While ICMP is critical for networking, attackers exploit its trusted status for stealthy attacks. Zero-trust 
segmentation, encryption, and strict filtering are key to defence.

## Emerging defence trends

* ML-Based Traffic Profiling: Detecting ICMP tunnels via entropy analysis of payloads (for example Palo Alto ML-Powered NGFW).
* QUIC/HTTP/3 Monitoring: ICMP used for QUIC path validation—filter malicious probes.
* Hardware-Assisted Filtering: SmartNICs offloading ICMP flood mitigation (for example AWS Nitro Cards).

