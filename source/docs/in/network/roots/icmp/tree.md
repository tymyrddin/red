# Overview attacks on ICMP

## Attack tree

This attack tree methodically catalogs the exploitation of ICMP and its IPv6 counterpart, ICMPv6, illustrating how these protocols can be weaponised for everything from stealthy reconnaissance and covert data exfiltration to disruptive denial-of-service attacks and sophisticated lateral movement within modern cloud and IoT environments.

```text
1. Reconnaissance & Network Mapping [OR]

    1.1 ICMP Echo Sweeping (Ping Sweep) [OR]
    
        1.1.1 High-speed parallel scanning [OR]
            1.1.1.1 Fping mass parallel ICMP probes
            1.1.1.2 Masscan with ICMP-only mode
            1.1.1.3 Zmap IPv6 ping6 sweeping
            
        1.1.2 Stealth scanning techniques [OR]
            1.1.2.1 Low-rate ICMP probes to evade detection
            1.1.2.2 Randomised probe timing (jitter)
            1.1.2.3 Source IP rotation through compromised hosts
            
        1.1.3 Protocol variation scanning [OR]
            1.1.3.1 ICMPv6 Node Information Queries
            1.1.3.2 Multicast Listener Discovery spoofing
            1.1.3.3 Neighbour Solicitation abuse

    1.2 TTL Manipulation for OS Fingerprinting [AND]
    
        1.2.1 TTL decay analysis [OR]
            1.2.1.1 Initial TTL value fingerprinting
            1.2.1.2 Hop count deduction from TTL decay
            1.2.1.3 IPv6 hop limit pattern analysis
            
        1.2.2 Advanced TTL probing [OR]
            1.2.2.1 Multi-packet TTL correlation
            1.2.2.2 TCP/UDP TTL bouncing
            1.2.2.3 ICMP error message TTL analysis
            
        1.2.3 Evasive fingerprinting [OR]
            1.2.3.1 Fragmentated TTL probes
            1.2.3.2 ICMP timestamp-based OS detection
            1.2.3.3 IPv6 extension header manipulation

    1.3 ICMP-based Service Discovery [OR]
    
        1.3.1 Legacy ICMP exploitation [OR]
            1.3.1.1 ICMP Timestamp Request abuse
            1.3.1.2 ICMP Address Mask Request probing
            1.3.1.3 Information Request exploitation
            
        1.3.2 IPv6-specific discovery [OR]
            1.3.2.1 ICMPv6 Router Solicitation scanning
            1.3.2.2 Multicast Listener Discovery queries
            1.3.2.3 Neighbour Advertisement spoofing
            
        1.3.3 Cloud environment mapping [OR]
            1.3.3.1 ICMP-based cloud provider identification
            1.3.3.2 VPC/VNet boundary discovery
            1.3.3.3 Container network mapping via ICMP

2. Data Exfiltration & Covert Channels [OR]

    2.1 ICMP Tunneling [AND]
    
        2.1.1 Payload encoding techniques [OR]
            2.1.1.1 ICMP Echo payload data encoding
            2.1.1.2 ICMPv6 option field exploitation
            2.1.1.3 Checksum manipulation for data carrying
            
        2.1.2 Tool-based tunneling [OR]
            2.1.2.1 Icmptunnel IPv6-enabled tunneling
            2.1.2.2 Ptunnel advanced ICMP tunneling
            2.1.2.3 Custom ICMP proxy development
            
        2.1.3 Evasion mechanisms [OR]
            2.1.3.1 Traffic shaping to mimic legitimate ICMP
            2.1.3.2 Multiple tunnel endpoint rotation
            2.1.3.3 Encrypted payload encapsulation

    2.2 Fragmented ICMP Exfiltration [OR]
    
        2.2.1 IPv6 fragmentation abuse [OR]
            2.2.1.1 IPv6 jumbogram exploitation
            2.2.1.2 Fragment header manipulation
            2.2.1.3 DPI evasion through fragment reassembly
            
        2.2.2 Payload distribution techniques [OR]
            2.2.2.1 Split payloads across multiple ICMP packets
            2.2.2.2 Time-distributed fragment transmission
            2.2.2.3 Geographic fragment distribution
            
        2.2.3 Stealth fragmentation [OR]
            2.2.3.1 Legitimate-looking fragment patterns
            2.2.3.2 MTU discovery integration
            2.2.3.3 ICMP error message fragmentation

    2.3 DNS-over-ICMP (C2) [AND]
    
        2.3.1 Protocol encapsulation [OR]
            2.3.1.1 DNS query encoding in ICMP Echo
            2.3.1.2 ICMPv6 Router Advertisement DNS injection
            2.3.1.3 Neighbour Discovery option abuse
            
        2.3.2 Malware integration [OR]
            2.3.2.1 MosaicLoader-style ICMP callbacks
            2.3.2.2 APT41 ICMP-based C2 channels
            2.3.2.3 IoT botnet ICMP command systems
            
        2.3.3 Evasive C2 techniques [OR]
            2.3.3.1 Dynamic encoding algorithm rotation
            2.3.3.2 Legitimate traffic mimicry
            2.3.3.3 Multi-protocol fallback mechanisms

3. Denial-of-Service (DoS) & Amplification [OR]

    3.1 ICMP Floods [OR]
    
        3.1.1 Direct flood attacks [OR]
            3.1.1.1 IPv6 ping6 high-volume floods
            3.1.1.2 ICMPv6 parameter problem floods
            3.1.1.3 Multicast listener report floods
            
        3.1.2 Spoofed-source attacks [OR]
            3.1.2.1 ICMPv6 spoofed-source floods
            3.1.2.2 Reflection through compromised infrastructure
            3.1.2.3 Botnet-based distributed flooding
            
        3.1.3 Protocol-specific floods [OR]
            3.1.3.1 Neighbour Solicitation storms
            3.1.3.2 Router Advertisement flooding
            3.1.3.3 MLD report exhaustion attacks

    3.2 ICMP Amplification [AND]
    
        3.2.1 Amplification vector exploitation [OR]
            3.2.1.1 "Packet Too Big" message amplification
            3.2.1.2 ICMPv6 error message reflection
            3.2.1.3 MTU discovery amplification
            
        3.2.2 Cloud infrastructure abuse [OR]
            3.2.2.1 Misconfigured cloud router exploitation
            3.2.2.2 Container network amplification
            3.2.2.3 Serverless function reflection
            
        3.2.3 High-gain amplification [OR]
            3.2.3.1 IPv6 jumbogram amplification
            3.2.3.2 Nested ICMP message exploitation
            3.2.3.3 Multi-protocol chain amplification

    3.3 Ping of Death (Modern Variants) [OR]
    
        3.3.1 IPv6 jumbo frame attacks [OR]
            3.3.1.1 IoT kernel jumbo frame exploitation
            3.3.1.2 Router fragment reassembly attacks
            3.3.1.3 Switch buffer exhaustion
            
        3.3.2 Malformed packet attacks [OR]
            3.3.2.1 ICMPv6 malformed extension headers
            3.3.2.2 Checksum manipulation crashes
            3.3.2.3 Option field corruption
            
        3.3.3 Hardware-specific exploits [OR]
            3.3.3.1 Network card firmware vulnerabilities
            3.3.3.2 Switch ASIC handling vulnerabilities
            3.3.3.3 IoT device stack corruption

4. Evasion & Protocol Abuse [OR]

    4.1 NAT/Firewall Bypass [AND]
    
        4.1.1 Callback mechanisms [OR]
            4.1.1.1 ICMP Echo Reply callback channels
            4.1.1.2 ICMPv6 informational message abuse
            4.1.1.3 Router Solicitation callbacks
            
        4.1.2 Whitelist exploitation [OR]
            4.1.2.1 PMTUD (Path MTU Discovery) abuse
            4.1.2.2 ICMP error message whitelist bypass
            4.1.2.3 IPv6 required ICMPv6 type exploitation
            
        4.1.3 Stateful firewall evasion [OR]
            4.1.3.1 ICMP session table manipulation
            4.1.3.2 Timeout exploitation for persistence
            4.1.3.3 Fragment-based state table attacks

    4.2 Lateral Movement via ICMP [OR]
    
        4.2.1 Advanced persistent threat techniques [OR]
            4.2.1.1 APT29-style internal C2 channels
            4.2.1.2 APT41 ICMP-based lateral movement
            4.2.1.3 Equation Group ICMP tradecraft
            
        4.2.2 Authentication abuse [OR]
            4.2.2.1 ICMP-based password spraying
            4.2.2.2 Network service discovery via ICMP
            4.2.2.3 Trust relationship exploitation
            
        4.2.3 Container/cloud lateral movement [OR]
            4.2.3.1 Kubernetes pod-to-pod ICMP tunnels
            4.2.3.2 Cloud VPC ICMP-based traversal
            4.2.3.3 Serverless function ICMP communication

    4.3 ICMPv6 Router Advertisement Spoofing [AND]
    
        4.3.1 Rogue RA attacks [OR]
            4.3.1.1 Default gateway impersonation
            4.3.1.2 DNS server injection via RAs
            4.3.1.3 Route preference manipulation
            
        4.3.2 Neighbour Discovery exploitation [OR]
            4.3.2.1 Weak IPv6 neighbour discovery abuse
            4.3.2.2 Duplicate Address Detection spoofing
            4.3.2.3 Neighbour Cache poisoning
            
        4.3.3 SLAAC attacks [OR]
            4.3.3.1 IPv6 address configuration manipulation
            4.3.3.2 Privacy extension exploitation
            4.3.3.3 Temporary address collision attacks

5. Zero-Day & Hardware Exploits [OR]

    5.1 ICMP Side-Channel Attacks [OR]
    
        5.1.1 Microarchitectural attacks [OR]
            5.1.1.1 NetSpectre-style timing leaks
            5.1.1.2 Cache timing via ICMP response
            5.1.1.3 Branch prediction influence
            
        5.1.2 Cloud environment inference [OR]
            5.1.2.1 VM placement inference via ICMP TTL
            5.1.2.2 Container orchestration detection
            5.1.2.3 Cloud provider fingerprinting
            
        5.1.3 Network topology leakage [OR]
            5.1.3.1 ICMP-based route inference
            5.1.3.2 Load balancer detection
            5.1.3.3 Network segmentation mapping

    5.2 IoT/OT Device Crashes [AND]
    
        5.2.1 Protocol stack exploitation [OR]
            5.2.1.1 Malformed ICMPv6 to embedded devices
            5.2.1.2 Resource exhaustion through ICMP
            5.2.1.3 Firmware bug triggers (CVE-2020-10148)
            
        5.2.2 Industrial system targeting [OR]
            5.2.2.1 SCADA system ICMP vulnerabilities
            5.2.2.2 PLC ICMP stack corruption
            5.2.2.3 OT network protocol attacks
            
        5.2.3 Supply chain vulnerabilities [OR]
            5.2.3.1 Vendor-specific ICMP implementations
            5.2.3.2 Custom protocol stack exploits
            5.2.3.3 Legacy system compatibility attacks

    5.3 Cloud Metadata Service Abuse [OR]
    
        5.3.1 IMDS exploitation [OR]
            5.3.1.1 ICMP-based IMDSv1 queries (AWS)
            5.3.1.2 Instance metadata service discovery
            5.3.1.3 Cloud credential harvesting
            
        5.3.2 Serverless SSRF attacks [OR]
            5.3.2.1 ICMP-triggered serverless SSRF
            5.3.2.2 Container metadata service access
            5.3.2.3 Kubernetes API server targeting
            
        5.3.3 Cloud network reconnaissance [OR]
            5.3.3.1 VPC metadata discovery via ICMP
            5.3.3.2 Cloud security group mapping
            5.3.3.3 Service endpoint discovery

6. AI/ML-Enhanced ICMP Attacks [OR]

    6.1 Adaptive Evasion Techniques [AND]
    
        6.1.1 Machine learning-based timing [OR]
            6.1.1.1 Reinforcement learning for probe timing
            6.1.1.2 Neural network-based traffic shaping
            6.1.1.3 Generative adversarial network evasion
            
        6.1.2 Behavioural mimicry [OR]
            6.1.2.1 Legitimate ICMP traffic generation
            6.1.2.2 Network monitoring system spoofing
            6.1.2.3 Anomaly detection bypass
            
        6.1.3 Dynamic protocol manipulation [OR]
            6.1.3.1 AI-generated ICMP payloads
            6.1.3.2 Adaptive checksum manipulation
            6.1.3.3 Intelligent fragment distribution

    6.2 Autonomous Attack Systems [OR]
    
        6.2.1 Self-learning C2 channels [OR]
            6.2.1.1 AI-managed ICMP tunneling
            6.2.1.2 Autonomous protocol switching
            6.2.1.3 Adaptive encoding techniques
            
        6.2.2 Intelligent reconnaissance [OR]
            6.2.2.1 ML-powered network mapping
            6.2.2.2 Predictive topology analysis
            6.2.2.3 Automated vulnerability identification
            
        6.2.3 Coordinated attack campaigns [OR]
            6.2.3.1 Multi-vector ICMP attack coordination
            6.2.3.2 Swarm intelligence for DDoS
            6.2.3.3 Distributed learning for evasion

7. Defensive Bypass & Anti-Forensics [OR]

    7.1 Forensic Evasion Techniques [OR]
    
        7.1.1 Log manipulation [OR]
            7.1.1.1 ICMP log entry spoofing
            7.1.1.2 Security system log poisoning
            7.1.1.3 Forensic timeline manipulation
            
        7.1.2 Evidence destruction [OR]
            7.1.2.1 ICMP-based log deletion triggers
            7.1.2.2 Network device configuration erasure
            7.1.2.3 Forensic tool interference
            
        7.1.3 Attribution obfuscation [OR]
            7.1.3.1 False flag ICMP campaigns
            7.1.3.2 Source address manipulation
            7.1.3.3 Geographic obfuscation

    7.2 Security Control Bypass [OR]
    
        7.2.1 IDS/IPS evasion [OR]
            7.2.1.1 ICMP signature avoidance
            7.2.1.2 Behavioral analysis bypass
            7.2.1.3 Machine learning model poisoning
            
        7.2.2 Network segmentation bypass [OR]
            7.2.2.1 ICMP-based segment hopping
            7.2.2.2 Firewall rule exploitation
            7.2.2.3 VLAN hopping via ICMP
            
        7.2.3 Cloud security bypass [OR]
            7.2.3.1 Security group rule exploitation
            7.2.3.2 Cloud firewall ICMP abuse
            7.2.3.3 Container security policy evasion
```

## Nitty gritty risk table

| Attack Path                                           | Technical Complexity | Resources Required | Risk Level | Notes                                                                                  |
|-------------------------------------------------------|----------------------|--------------------|------------|----------------------------------------------------------------------------------------|
| 1.1.1.1 Fping mass parallel ICMP probes               | Low                  | Low                | Low        | Simple to execute with open-source tools; effective for quick host discovery.          |
| 1.1.1.2 Masscan with ICMP-only mode                   | Low                  | Low                | Low        | High-speed scanning; requires minimal resources but may trigger alarms.                |
| 1.1.1.3 Zmap IPv6 ping6 sweeping                      | Medium               | Low                | Medium     | IPv6-specific; requires knowledge of IPv6 addressing but efficient for large networks. |
| 1.1.2.1 Low-rate ICMP probes to evade detection       | Medium               | Low                | Medium     | Stealthy approach; requires timing control to avoid IDS thresholds.                    |
| 1.1.2.2 Randomised probe timing (jitter)              | Medium               | Low                | Medium     | Adds variability to avoid pattern detection; simple to implement.                      |
| 1.1.2.3 Source IP rotation through compromised hosts  | High                 | Medium             | High       | Uses botnets or proxies; increases anonymity but requires existing compromises.        |
| 1.1.3.1 ICMPv6 Node Information Queries               | High                 | Low                | Medium     | IPv6-specific reconnaissance; can reveal host details without full scans.              |
| 1.1.3.2 Multicast Listener Discovery spoofing         | High                 | Medium             | High       | Targets IPv6 multicast groups; can map listeners and services.                         |
| 1.1.3.3 Neighbour Solicitation abuse                  | High                 | Low                | Medium     | Exploits IPv6 Neighbour Discovery Protocol; effective for local network mapping.       |
| 1.2.1.1 Initial TTL value fingerprinting              | Low                  | Low                | Low        | Basic OS detection; relies on default TTL values but easily automated.                 |
| 1.2.1.2 Hop count deduction from TTL decay            | Medium               | Low                | Medium     | Estimates network topology; requires analysis but low resource cost.                   |
| 1.2.1.3 IPv6 hop limit pattern analysis               | Medium               | Low                | Medium     | IPv6 variant; similar to TTL but with hop limit field.                                 |
| 1.2.2.1 Multi-packet TTL correlation                  | High                 | Low                | Medium     | Advanced technique to improve accuracy; requires multiple probes.                      |
| 1.2.2.2 TCP/UDP TTL bouncing                          | High                 | Medium             | High       | Uses ancillary protocols for evasion; complex but stealthy.                            |
| 1.2.2.3 ICMP error message TTL analysis               | High                 | Low                | Medium     | Analyses error responses; can reveal paths and devices.                                |
| 1.2.3.1 Fragmentated TTL probes                       | High                 | Low                | High       | Uses fragmentation to evade filters; may be blocked in modern networks.                |
| 1.2.3.2 ICMP timestamp-based OS detection             | Medium               | Low                | Medium     | Leverages timestamp requests; less common but still effective.                         |
| 1.2.3.3 IPv6 extension header manipulation            | Very High            | Medium             | High       | Advanced IPv6 exploitation; requires deep protocol knowledge.                          |
| 1.3.1.1 ICMP Timestamp Request abuse                  | Low                  | Low                | Low        | Legacy technique; rarely used but can provide host information.                        |
| 1.3.1.2 ICMP Address Mask Request probing             | Low                  | Low                | Low        | Obsolete in modern networks but may work on older systems.                             |
| 1.3.1.3 Information Request exploitation              | Low                  | Low                | Low        | Historical protocol feature; unlikely to be supported nowadays.                        |
| 1.3.2.1 ICMPv6 Router Solicitation scanning           | Medium               | Low                | Medium     | IPv6-specific; can discover routers and network parameters.                            |
| 1.3.2.2 Multicast Listener Discovery queries          | Medium               | Low                | Medium     | Maps multicast services; useful for service discovery.                                 |
| 1.3.2.3 Neighbour Advertisement spoofing              | High                 | Low                | High       | Can poison IPv6 caches; leads to MITM or DoS.                                          |
| 1.3.3.1 ICMP-based cloud provider identification      | Medium               | Low                | Medium     | Uses TTL or response patterns to identify cloud environments.                          |
| 1.3.3.2 VPC/VNet boundary discovery                   | High                 | Low                | High       | Maps cloud network boundaries; valuable for lateral movement.                          |
| 1.3.3.3 Container network mapping via ICMP            | High                 | Low                | High       | Targets containerised environments; can escape network segments.                       |
| 2.1.1.1 ICMP Echo payload data encoding               | Medium               | Low                | Medium     | Simple tunneling; hides data in ping packets but detectable with deep inspection.      |
| 2.1.1.2 ICMPv6 option field exploitation              | High                 | Low                | High       | Uses IPv6 extension headers; more stealthy but complex to implement.                   |
| 2.1.1.3 Checksum manipulation for data carrying       | High                 | Low                | High       | Alters checksums to encode data; evades basic checks but risky for reliability.        |
| 2.1.2.1 Icmptunnel IPv6-enabled tunneling             | Medium               | Low                | Medium     | Open-source tool; easy to use but well-known and detectable.                           |
| 2.1.2.2 Ptunnel advanced ICMP tunneling               | High                 | Low                | High       | More advanced than Icmptunnel; supports encryption and evasion.                        |
| 2.1.2.3 Custom ICMP proxy development                 | Very High            | High               | Very High  | Tailored to specific environments; highly stealthy but requires development effort.    |
| 2.1.3.1 Traffic shaping to mimic legitimate ICMP      | High                 | Medium             | High       | Blends with normal ICMP traffic; difficult to detect without behavioural analysis.     |
| 2.1.3.2 Multiple tunnel endpoint rotation             | High                 | Medium             | High       | Changes endpoints to avoid blacklisting; requires infrastructure.                      |
| 2.1.3.3 Encrypted payload encapsulation               | Very High            | Medium             | Very High  | Adds encryption to tunneling; prevents content inspection but may attract attention.   |
| 2.2.1.1 IPv6 jumbogram exploitation                   | Very High            | Low                | High       | Uses large IPv6 packets for data transfer; may be blocked or misconfigured.            |
| 2.2.1.2 Fragment header manipulation                  | High                 | Low                | High       | Alters fragmentation for evasion; complex and prone to failure.                        |
| 2.2.1.3 DPI evasion through fragment reassembly       | Very High            | Low                | Very High  | Bypasses deep packet inspection; requires precise timing and packet crafting.          |
| 2.2.2.1 Split payloads across multiple ICMP packets   | Medium               | Low                | Medium     | Simple data distribution; inefficient but avoids size thresholds.                      |
| 2.2.2.2 Time-distributed fragment transmission        | High                 | Low                | High       | Spreads packets over time to evade detection; requires patience.                       |
| 2.2.2.3 Geographic fragment distribution              | Very High            | High               | Very High  | Uses diverse paths; hard to trace but needs global infrastructure.                     |
| 2.2.3.1 Legitimate-looking fragment patterns          | High                 | Low                | High       | Mimics normal traffic; effective against simple filters.                               |
| 2.2.3.2 MTU discovery integration                     | High                 | Low                | High       | Exploits path MTU discovery; blends with legitimate network operations.                |
| 2.2.3.3 ICMP error message fragmentation              | Very High            | Low                | Very High  | Rarely monitored; highly stealthy but technically complex.                             |
| 2.3.1.1 DNS query encoding in ICMP Echo               | Medium               | Low                | Medium     | Hides DNS in ICMP; bypasses DNS monitoring but detectable with analysis.               |
| 2.3.1.2 ICMPv6 Router Advertisement DNS injection     | High                 | Low                | High       | Targets IPv6 autoconfiguration; can redirect or poison DNS.                            |
| 2.3.1.3 Neighbour Discovery option abuse              | High                 | Low                | High       | Uses IPv6 ND for C2; stealthy but requires local network access.                       |
| 2.3.2.1 MosaicLoader-style ICMP callbacks             | High                 | Medium             | High       | Real-world malware technique; effective for persistent C2.                             |
| 2.3.2.2 APT41 ICMP-based C2 channels                  | Very High            | High               | Very High  | Advanced threat actor tactic; highly evasive and persistent.                           |
| 2.3.2.3 IoT botnet ICMP command systems               | Medium               | Low                | High       | Common in IoT attacks; low cost but scalable.                                          |
| 2.3.3.1 Dynamic encoding algorithm rotation           | High                 | Medium             | High       | Changes encoding to avoid signatures; requires advanced C2 infrastructure.             |
| 2.3.3.2 Legitimate traffic mimicry                    | Very High            | Medium             | Very High  | Mimics common ICMP patterns; extremely hard to detect.                                 |
| 2.3.3.3 Multi-protocol fallback mechanisms            | Very High            | High               | Very High  | Switches protocols if blocked; ensures reliability but complex to implement.           |
| 3.1.1.1 IPv6 ping6 high-volume floods                 | Low                  | High               | High       | Simple but effective; requires high bandwidth for impact.                              |
| 3.1.1.2 ICMPv6 parameter problem floods               | Medium               | Medium             | High       | Targets IPv6 stacks; can cause devices to crash or slow down.                          |
| 3.1.1.3 Multicast listener report floods              | High                 | Medium             | High       | Swamps multicast networks; disruptive to multicast-dependent services.                 |
| 3.1.2.1 ICMPv6 spoofed-source floods                  | Medium               | High               | High       | Hides source; amplifies impact but requires bandwidth.                                 |
| 3.1.2.2 Reflection through compromised infrastructure | High                 | High               | Very High  | Uses third-party systems; increases scale and anonymity.                               |
| 3.1.2.3 Botnet-based distributed flooding             | Medium               | High               | Very High  | Leverages botnets; high impact and hard to mitigate.                                   |
| 3.1.3.1 Neighbour Solicitation storms                 | High                 | Medium             | High       | Targets IPv6 networks; can exhaust resources or cause MITM.                            |
| 3.1.3.2 Router Advertisement flooding                 | High                 | Medium             | High       | Spams RAs; disrupts network configuration and stability.                               |
| 3.1.3.3 MLD report exhaustion attacks                 | High                 | Medium             | High       | Floods Multicast Listener Discovery; impacts multicast routing.                        |
| 3.2.1.1 "Packet Too Big" message amplification        | High                 | Medium             | High       | Amplifies attacks using ICMP errors; can achieve high gain.                            |
| 3.2.1.2 ICMPv6 error message reflection               | High                 | Medium             | High       | Reflects attacks through misconfigured devices; hides source.                          |
| 3.2.1.3 MTU discovery amplification                   | Very High            | Medium             | Very High  | Exploits MTU discovery process; complex but potent.                                    |
| 3.2.2.1 Misconfigured cloud router exploitation       | Medium               | Low                | High       | Uses cloud routers reflectors; easy if misconfigurations exist.                        |
| 3.2.2.2 Container network amplification               | High                 | Medium             | High       | Targets container networks; can scale within cloud environments.                       |
| 3.2.2.3 Serverless function reflection                | High                 | Low                | High       | Abuses serverless platforms; low cost and highly scalable.                             |
| 3.2.3.1 IPv6 jumbogram amplification                  | Very High            | High               | Very High  | Uses large packets for amplification; requires jumbogram support.                      |
| 3.2.3.2 Nested ICMP message exploitation              | Very High            | High               | Very High  | Crafts complex ICMP structures; rare and highly impactful.                             |
| 3.2.3.3 Multi-protocol chain amplification            | Very High            | High               | Very High  | Combines multiple protocols; maximum amplification but technically complex.            |
| 3.3.1.1 IoT kernel jumbo frame exploitation           | High                 | Low                | High       | Crashes IoT devices; effective due to poor stack implementations.                      |
| 3.3.1.2 Router fragment reassembly attacks            | High                 | Low                | High       | Overwhelms reassembly buffers; causes crashes or resource exhaustion.                  |
| 3.3.1.3 Switch buffer exhaustion                      | Medium               | Low                | Medium     | Floods switches with fragments; disrupts network performance.                          |
| 3.3.2.1 ICMPv6 malformed extension headers            | Very High            | Low                | High       | Targets IPv6 stack parsing; can lead to crashes or code execution.                     |
| 3.3.2.2 Checksum manipulation crashes                 | High                 | Low                | High       | Invalid checksums cause stack errors; unpredictable results.                           |
| 3.3.2.3 Option field corruption                       | High                 | Low                | High       | Corrupts ICMP options; may exploit specific vulnerabilities.                           |
| 3.3.3.1 Network card firmware vulnerabilities         | Very High            | High               | Very High  | Rare and valuable; can persist across reboots.                                         |
| 3.3.3.2 Switch ASIC handling vulnerabilities          | Very High            | High               | Very High  | Hardware-level exploits; devastating but require specific expertise.                   |
| 3.3.3.3 IoT device stack corruption                   | High                 | Low                | High       | Common due to poor coding; easily automated for large-scale attacks.                   |
| 4.1.1.1 ICMP Echo Reply callback channels             | Medium               | Low                | Medium     | Simple callback mechanism; detectable if outgoing ICMP is monitored.                   |
| 4.1.1.2 ICMPv6 informational message abuse            | High                 | Low                | High       | Uses less-common ICMPv6 types; often allowed through firewalls.                        |
| 4.1.1.3 Router Solicitation callbacks                 | High                 | Low                | High       | Leverages IPv6 autoconfiguration; stealthy and effective.                              |
| 4.1.2.1 PMTUD (Path MTU Discovery) abuse              | High                 | Low                | High       | Exploits necessary ICMP messages; often whitelisted and trusted.                       |
| 4.1.2.2 ICMP error message whitelist bypass           | Medium               | Low                | Medium     | Uses allowed ICMP types; simple but depends on firewall rules.                         |
| 4.1.2.3 IPv6 required ICMPv6 type exploitation        | High                 | Low                | High       | Targets essential IPv6 operations; hard to block without breaking functionality.       |
| 4.1.3.1 ICMP session table manipulation               | High                 | Low                | High       | Exhausts state tables; can bypass stateful firewalls.                                  |
| 4.1.3.2 Timeout exploitation for persistence          | Medium               | Low                | Medium     | Keeps sessions open longer; evades timeout-based cleanup.                              |
| 4.1.3.3 Fragment-based state table attacks            | High                 | Low                | High       | Uses fragments to confuse stateful devices; complex but effective.                     |
| 4.2.1.1 APT29-style internal C2 channels              | Very High            | High               | Very High  | Advanced persistent threat tactic; highly stealthy and persistent.                     |
| 4.2.1.2 APT41 ICMP-based lateral movement             | Very High            | High               | Very High  | Real-world example; uses ICMP for internal propagation.                                |
| 4.2.1.3 Equation Group ICMP tradecraft                | Very High            | High               | Very High  | Nation-state level; sophisticated and hard to detect.                                  |
| 4.2.2.1 ICMP-based password spraying                  | Medium               | Low                | Medium     | Uses ICMP to deliver spray attacks; evades traditional security controls.              |
| 4.2.2.2 Network service discovery via ICMP            | Medium               | Low                | Medium     | Finds services without port scans; stealthy but limited to ICMP-accessible info.       |
| 4.2.2.3 Trust relationship exploitation               | High                 | Low                | High       | Uses ICMP to traverse trust boundaries; requires prior knowledge.                      |
| 4.2.3.1 Kubernetes pod-to-pod ICMP tunnels            | High                 | Low                | High       | Escapes container isolation; effective in cloud environments.                          |
| 4.2.3.2 Cloud VPC ICMP-based traversal                | High                 | Low                | High       | Moves between cloud segments; leverages allowed ICMP traffic.                          |
| 4.2.3.3 Serverless function ICMP communication        | High                 | Low                | High       | Uses ICMP for inter-function communication; hard to monitor.                           |
| 4.3.1.1 Default gateway impersonation                 | High                 | Low                | High       | Rogue RAs mimic gateways; leads to MITM or traffic interception.                       |
| 4.3.1.2 DNS server injection via RAs                  | High                 | Low                | High       | Injects malicious DNS through RAs; can redirect traffic or steal data.                 |
| 4.3.1.3 Route preference manipulation                 | Medium               | Low                | Medium     | Alters route preferences; influences traffic paths subtly.                             |
| 4.3.2.1 Weak IPv6 neighbour discovery abuse           | High                 | Low                | High       | Exploits insecure ND implementations; common in legacy networks.                       |
| 4.3.2.2 Duplicate Address Detection spoofing          | High                 | Low                | High       | Prevents legitimate addresses from being used; causes DoS or takeover.                 |
| 4.3.2.3 Neighbour Cache poisoning                     | High                 | Low                | High       | Corrupts ARP-like caches in IPv6; facilitates MITM attacks.                            |
| 4.3.3.1 IPv6 address configuration manipulation       | High                 | Low                | High       | Alters SLAAC assignments; can assign addresses for MITM.                               |
| 4.3.3.2 Privacy extension exploitation                | High                 | Low                | High       | Predicts or influences temporary addresses; undermines privacy.                        |
| 4.3.3.3 Temporary address collision attacks           | High                 | Low                | High       | Causes address conflicts; disrupts communication or enables takeover.                  |
| 5.1.1.1 NetSpectre-style timing leaks                 | Very High            | Medium             | Very High  | Remote side-channel attack; requires high precision and analysis.                      |
| 5.1.1.2 Cache timing via ICMP response                | Very High            | Medium             | Very High  | Measures response times to infer cache state; complex and slow.                        |
| 5.1.1.3 Branch prediction influence                   | Very High            | High               | Very High  | Affects CPU branch prediction; theoretical but potentially devastating.                |
| 5.1.2.1 VM placement inference via ICMP TTL           | High                 | Low                | Medium     | Deduces cloud infrastructure; useful for targeting specific instances.                 |
| 5.1.2.2 Container orchestration detection             | High                 | Low                | Medium     | Identifies Kubernetes or similar; helps in containerised attacks.                      |
| 5.1.2.3 Cloud provider fingerprinting                 | Medium               | Low                | Low        | Uses TTL or other traits to identify providers; low risk but informative.              |
| 5.1.3.1 ICMP-based route inference                    | High                 | Low                | Medium     | Maps network paths; valuable for reconnaissance.                                       |
| 5.1.3.2 Load balancer detection                       | Medium               | Low                | Medium     | Identifies load balancers via TTL or response patterns.                                |
| 5.1.3.3 Network segmentation mapping                  | High                 | Low                | High       | Uses ICMP to deduce network segments; aids in lateral movement.                        |
| 5.2.1.1 Malformed ICMPv6 to embedded devices          | High                 | Low                | High       | Crashes or compromises IoT devices; common due to weak stacks.                         |
| 5.2.1.2 Resource exhaustion through ICMP              | Medium               | Low                | Medium     | Floods devices with ICMP; causes DoS or instability.                                   |
| 5.2.1.3 Firmware bug triggers (CVE-2020-10148)        | Medium               | Low                | High       | Exploits known vulnerabilities; easily automated for large-scale attacks.              |
| 5.2.2.1 SCADA system ICMP vulnerabilities             | High                 | Low                | Very High  | Targets industrial systems; can cause physical disruptions.                            |
| 5.2.2.2 PLC ICMP stack corruption                     | High                 | Low                | Very High  | Programmable Logic Controllers often have weak networks stacks.                        |
| 5.2.2.3 OT network protocol attacks                   | Very High            | Medium             | Very High  | Operational Technology focus; requires specialised knowledge.                          |
| 5.2.3.1 Vendor-specific ICMP implementations          | High                 | Low                | High       | Exploits custom firmware; effective against niche devices.                             |
| 5.2.3.2 Custom protocol stack exploits                | Very High            | High               | Very High  | Targets proprietary stacks; valuable zero-days.                                        |
| 5.2.3.3 Legacy system compatibility attacks           | Medium               | Low                | Medium     | Exploits old systems still in use; low hanging fruit.                                  |
| 5.3.1.1 ICMP-based IMDSv1 queries (AWS)               | Medium               | Low                | High       | Accesses cloud metadata; can lead to credential theft.                                 |
| 5.3.1.2 Instance metadata service discovery           | Medium               | Low                | Medium     | Finds metadata services; reconnaissance step for further attacks.                      |
| 5.3.1.3 Cloud credential harvesting                   | High                 | Low                | Very High  | Steals credentials via metadata; devastating for cloud security.                       |
| 5.3.2.1 ICMP-triggered serverless SSRF                | High                 | Low                | High       | Uses ICMP to induce serverless SSRF; bypasses common guards.                           |
| 5.3.2.2 Container metadata service access             | High                 | Low                | High       | Targets container metadata; similar to cloud instance attacks.                         |
| 5.3.2.3 Kubernetes API server targeting               | High                 | Low                | Very High  | Compromises K8s API via metadata; cluster-wide impact.                                 |
| 5.3.3.1 VPC metadata discovery via ICMP               | Medium               | Low                | Medium     | Maps cloud network metadata; reconnaissance for lateral movement.                      |
| 5.3.3.2 Cloud security group mapping                  | High                 | Low                | High       | Uses ICMP responses to deduce firewall rules.                                          |
| 5.3.3.3 Service endpoint discovery                    | Medium               | Low                | Medium     | Finds cloud services; helps in targeting critical assets.                              |
| 6.1.1.1 Reinforcement learning for probe timing       | Very High            | High               | Very High  | AI-driven evasion; adapts to network conditions for stealth.                           |
| 6.1.1.2 Neural network-based traffic shaping          | Very High            | High               | Very High  | Generates traffic patterns that mimic legitimate behaviour.                            |
| 6.1.1.3 Generative adversarial network evasion        | Very High            | High               | Very High  | Uses GANs to create evasive traffic; cutting-edge and highly effective.                |
| 6.1.2.1 Legitimate ICMP traffic generation            | High                 | Medium             | High       | AI generates realistic ICMP; bypasses behavioural analysis.                            |
| 6.1.2.2 Network monitoring system spoofing            | Very High            | High               | Very High  | Tricks monitoring tools; requires deep knowledge of defence systems.                   |
| 6.1.2.3 Anomaly detection bypass                      | Very High            | High               | Very High  | AI learns and avoids detection thresholds; persistent evasion.                         |
| 6.1.3.1 AI-generated ICMP payloads                    | Very High            | High               | Very High  | Creates optimised payloads for specific targets or goals.                              |
| 6.1.3.2 Adaptive checksum manipulation                | Very High            | High               | Very High  | AI adjusts checksums to evade inspection while maintaining functionality.              |
| 6.1.3.3 Intelligent fragment distribution             | Very High            | High               | Very High  | AI decides fragment timing and size for maximum stealth.                               |
| 6.2.1.1 AI-managed ICMP tunneling                     | Very High            | High               | Very High  | Autonomous C2 channels that adapt and evolve.                                          |
| 6.2.1.2 Autonomous protocol switching                 | Very High            | High               | Very High  | Switches between protocols based on network conditions.                                |
| 6.2.1.3 Adaptive encoding techniques                  | Very High            | High               | Very High  | AI changes encoding in real-time to avoid detection.                                   |
| 6.2.2.1 ML-powered network mapping                    | Very High            | High               | Very High  | Rapid, intelligent reconnaissance with minimal footprint.                              |
| 6.2.2.2 Predictive topology analysis                  | Very High            | High               | Very High  | AI predicts network structures for better targeting.                                   |
| 6.2.2.3 Automated vulnerability identification        | Very High            | High               | Very High  | AI scans for and exploits weaknesses without human intervention.                       |
| 6.2.3.1 Multi-vector ICMP attack coordination         | Very High            | High               | Very High  | Coordinates different ICMP attacks for compounded effect.                              |
| 6.2.3.2 Swarm intelligence for DDoS                   | Very High            | High               | Very High  | Botnet-like coordination using AI for efficient DDoS.                                  |
| 6.2.3.3 Distributed learning for evasion              | Very High            | High               | Very High  | AI nodes share learning to improve evasion across the network.                         |
| 7.1.1.1 ICMP log entry spoofing                       | High                 | Low                | High       | Fakes log entries to mislead investigators.                                            |
| 7.1.1.2 Security system log poisoning                 | High                 | Low                | High       | Corrupts logs with false data; undermines forensic analysis.                           |
| 7.1.1.3 Forensic timeline manipulation                | Very High            | Medium             | Very High  | Alters timestamps to confuse event reconstruction.                                     |
| 7.1.2.1 ICMP-based log deletion triggers              | High                 | Low                | High       | Uses ICMP to signal log deletion; hard to trace.                                       |
| 7.1.2.2 Network device configuration erasure          | High                 | Low                | Very High  | Erases configs via ICMP; causes persistent damage.                                     |
| 7.1.2.3 Forensic tool interference                    | Very High            | High               | Very High  | Disrupts forensic tools with specially crafted ICMP.                                   |
| 7.1.3.1 False flag ICMP campaigns                     | High                 | Medium             | High       | Frames other entities; misdirects attribution.                                         |
| 7.1.3.2 Source address manipulation                   | Medium               | Low                | Medium     | Spoofs sources; common but less effective with modern tracing.                         |
| 7.1.3.3 Geographic obfuscation                        | High                 | Medium             | High       | Routes through multiple countries; complicates legal response.                         |
| 7.2.1.1 ICMP signature avoidance                      | Medium               | Low                | Medium     | Modifies packets to avoid IDS signatures; simple but effective.                        |
| 7.2.1.2 Behavioral analysis bypass                    | Very High            | High               | Very High  | Uses AI or advanced techniques to mimic normal behaviour.                              |
| 7.2.1.3 Machine learning model poisoning              | Very High            | High               | Very High  | Corrupts defensive AI models; sophisticated and damaging.                              |
| 7.2.2.1 ICMP-based segment hopping                    | High                 | Low                | High       | Uses ICMP to move between network segments.                                            |
| 7.2.2.2 Firewall rule exploitation                    | Medium               | Low                | Medium     | Finds and uses allowed ICMP rules to bypass filters.                                   |
| 7.2.2.3 VLAN hopping via ICMP                         | High                 | Low                | High       | Leverages ICMP in VLAN environments; rare but possible.                                |
| 7.2.3.1 Security group rule exploitation              | Medium               | Low                | Medium     | Uses overly permissive cloud rules; common misconfiguration.                           |
| 7.2.3.2 Cloud firewall ICMP abuse                     | Medium               | Low                | Medium     | Exploits cloud firewall defaults for ICMP.                                             |
| 7.2.3.3 Container security policy evasion             | High                 | Low                | High       | Bypasses container policies using ICMP; effective in Kubernetes.                       |

