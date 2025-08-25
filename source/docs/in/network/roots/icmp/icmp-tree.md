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
            
        6.1.2 Behavioral mimicry [OR]
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
