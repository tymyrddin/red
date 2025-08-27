# ICMP abuse (IPv4)

## Attack pattern

The Internet Control Message Protocol (ICMP) is essential for network diagnostics and error reporting. Attackers 
exploit its trusted nature and common misconfigurations for various malicious purposes.

```text
1. ICMP Abuse [OR]

    1.1 Volumetric Denial-of-Service (DoS) [OR]
    
        1.1.1 Smurf Attack
            1.1.1.1 Direct Broadcast Amplification
            1.1.1.2 Reflector Network Recruitment
            1.1.1.3 Multi-Vector Smurf (combining ICMP & UDP)
            
        1.1.2 ICMP Flood
            1.1.2.1 Direct Target Flood
            1.1.2.2 Router Infrastructure Flood
            1.1.2.3 Asymmetric Path Flood (using routing loops)
            
        1.1.3 Ping of Death (Historical)
            1.1.3.1 Oversized ICMPv4 Packet
            1.1.3.2 Malformed ICMPv6 Packet
            
    1.2 Covert Channels & Data Exfiltration [OR]
    
        1.2.1 ICMP Tunneling
            1.2.1.1 ICMP Echo (Ping) Request Tunneling
            1.2.1.2 ICMP Echo Reply Tunneling
            1.2.1.3 ICMP Timestamp Tunneling
            1.2.1.4 ICMP Destination Unreachable Tunneling
            
        1.2.2 Command and Control (C2)
            1.2.2.1 Beaconing via ICMP Echo Requests
            1.2.2.2 Payload Encoding in Identifier/Sequence Fields
            1.2.2.3 Data Encoding in Data Payload
            
    1.3 Network Reconnaissance & Mapping [OR]
    
        1.3.1 Host Discovery
            1.3.1.1 ICMP Echo Sweeping
            1.3.1.2 ICMP Timestamp Query Sweeping
            1.3.1.3 ICMP Address Mask Query Sweeping
            
        1.3.2 Path Discovery
            1.3.2.1 Traceroute Exploitation (TTL Expiry)
            1.3.2.2 Record Route Option Manipulation
            1.3.2.3 ICMP-based Firewall Mapping
            
    1.4 Protocol Manipulation & Evasion [OR]
    
        1.4.1 ICMP Redirect Attacks
            1.4.1.1 Route Table Poisoning
            1.4.1.2 Man-in-the-Middle (MitM) Facilitation
            
        1.4.2 ICMP Error Message Abuse
            1.4.2.1 TCP Connection Reset via ICMP Dest Unreachable
            1.4.2.2 Path MTU Discovery Exploitation
            1.4.2.3 ICMP Quench Message Abuse (Historical)
            
    1.5 State Exhaustion & Resource Depletion [OR]
    
        1.5.1 ICMP Error Storm
            1.5.1.1 Triggering Excessive ICMP Error Messages
            1.5.1.2 Router CPU Exhaustion via Error Generation
            
        1.5.2 Firewall State Table Exhaustion
            1.5.2.1 High-Rate ICMP Triggering State Creation
            1.5.2.2 Asymmetric ICMP Flow State Mismatch
```

## Why it works

-   Operational Necessity: ICMP is required for core network functions like Path MTU Discovery (PMTUD), error reporting, and connectivity tests (`ping`, `traceroute`). Blocking it entirely can break network functionality.
-   Permissive Configurations: Many firewalls and security groups are configured with overly broad ICMP allow rules (e.g., `permit icmp any any`) for simplicity.
-   Lack of Scrutiny: ICMP is often considered benign "maintenance" traffic, leading to a lack of monitoring, rate-limiting, and deep inspection compared to TCP or UDP.
-   Spoofability: The simplicity of the ICMP protocol makes it trivial to forge packets with a spoofed source IP, which is essential for Smurf attacks and some evasion techniques.

## Mitigation

### Rate limiting

-   Action: Implement granular rate limiting on ICMP message types.
-   How:
    -   Cisco IOS/XR: Use Control Plane Policing (CoPP) or interface rate-limiters.
        -   `policy-map CoPP-INPUT... class ICMP... police cir 256000 8000 conform-action transmit exceed-action drop`
    -   Linux (iptables): Use the `limit` module.
        -   `iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT`
    -   Cloud (AWS Network ACLs): Create rules that allow essential ICMP but are limited in scope and number.

### Egress filtering (BCP38)

-   Action: Prevent packets with spoofed source IPs from leaving your network.
-   How:
    -   Edge Routers: Implement ACLs on all external interfaces that only permit traffic out if the source IP belongs to your allocated range.
    -   Example (Cisco): `ip access-list extended INTERNET-OUT; permit ip [YOUR-PREFIX] any; deny ip any any log`
    -   Infrastructure: Enable Unicast Reverse Path Forwarding (uRPF) in strict mode on all border routers. This checks if the source IP of a packet is reachable via the interface it arrived on, dropping spoofed packets.

### Granular filtering

-   Action: Move from allowing all ICMP (`protocol icmp`) to permitting only specific, necessary ICMP types and codes.
-   How:
    -   Internet Edge: Inbound rules should typically only allow *ICMP Echo Reply*, *Destination Unreachable*, *Time Exceeded*, and *Parameter Problem* messages from the internet to your infrastructure. Block *ICMP Echo Request* (ping) from the internet.
    -   Internal Networks: Be more permissive internally but still avoid `any any`. Allow *Echo Request/Reply* and messages critical for PMTUD (*Packet Too Big* for IPv6 is crucial).
    -   Example ACL:
        -   `permit icmp any any echo-reply`
        -   `permit icmp any any parameter-problem`
        -   `permit icmp any any time-exceeded`
        -   `permit icmp any any unreachable`
        -   `deny icmp any any` (implicit, but explicit for logging)

### Deep Packet Inspection (DPI)

-   Action: Analyze ICMP packet payloads to detect anomalies indicative of tunneling or C2 traffic.
-   How:
    -   IPS/IDS Systems: Enable and tune signatures designed to detect ICMP tunneling. These signatures look for:
        -   Payload Size: Ping packets with consistently large or fixed-sized data payloads (unlike normal pings).
        -   Payload Content: Non-random, structured, or encrypted-looking data within the ICMP data field.
        -   Frequency & Pattern: Regular, beacon-like ICMP requests at fixed intervals from the same internal host.
    -   Network Traffic Analysis (NTA) Tools: Use tools like Zeek, Suricata, or commercial solutions to baseline normal ICMP traffic and alert on deviations in volume, size, or timing.
    -   Data Loss Prevention (DLP): Integrate DLP with network monitoring to scan ICMP payloads for specific data patterns being exfiltrated.