# IP fragmentation (IPv4)

## Attack pattern

An attacker deliberately crafts IP packets that are fragmented in an abnormal or malicious way. These packets are designed to exploit vulnerabilities in the target system's algorithm for reassembling fragments into a complete packet. The goals are:

1. System Crashes & Kernel Panics: By sending overlapping fragments (e.g., two fragments that write to the same memory location during reassembly) or extremely large fragments, the attacker can cause buffer overflows or logical errors in the IP stack, crashing the device.
2. Evasion of Security Controls: Many firewalls, Intrusion Detection Systems (IDS), and Intrusion Prevention Systems (IPS) perform initial inspection on the first fragment but may not have the capability or resources to fully reassemble all fragments before inspection. An attacker can hide malicious payload in subsequent fragments to bypass these controls.
3. Resource Exhaustion: Flooding a target with a high volume of fragments forces it to allocate memory and CPU cycles to reassembly, potentially exhausting resources and causing a Denial-of-Service (DoS) for legitimate traffic.

```text
1. IP Fragmentation Attacks [OR]

    1.1 Target Reassembly Algorithm Flaws [OR]
    
        1.1.1 Overlapping Fragment Attacks
            1.1.1.1 TCP Overlap (TearDrop)
            1.1.1.2 UDP Overlap (Jolt2)
            1.1.1.3 IP Fragment Overlap (Rose Attack)
            
        1.1.2 Out-of-Order Fragment Reassembly
            1.1.2.1 Fragment Number Zero Not First
            1.1.2.2 Missing Initial Fragment with Subsequent Fragments
            
        1.1.3 Maximum Fragment Size Exceedance
            1.1.3.1 Ping of Death (Oversized ICMP)
            1.1.3.2 Jumbo Fragment Heap Corruption
            
    1.2 Security Control Evasion [OR]
    
        1.2.1 IDS/IPS Evasion Techniques
            1.2.1.1 Time-To-Live (TTL) Based Evasion
            1.2.1.2 Fragment Timeout Mismatch
            1.2.1.3 Partial Fragment Stream Injection
            
        1.2.2 Firewall Rule Bypass
            1.2.2.1 Header Split Across Fragments
            1.2.2.2 Payload Distributed Across Multiple Fragments
            1.2.2.3 FIN Bit in Non-Initial Fragment
            
        1.2.3 Protocol Field Obfuscation
            1.2.3.1 Transport Protocol in Second Fragment
            1.2.3.2 Port Numbers in Non-Initial Fragments
            
    1.3 Resource Exhaustion Attacks [OR]
    
        1.3.1 Memory Consumption Attacks
            1.3.1.1 Fragment Buffer Flood
            1.3.1.2 Hash Table Collision Attack
            1.3.1.3 Reassembly Queue Overflow
            
        1.3.2 CPU Exhaustion Techniques
            1.3.2.1 High-Rate Fragment Injection
            1.3.2.2 Computational Complexity Attacks
            1.3.2.3 Reassembly Timer Manipulation
            
    1.4 Application Layer Attacks [OR]
    
        1.4.1 HTTP Fragmentation Attacks
            1.4.1.1 Chunked Encoding with Fragmentation
            1.4.1.2 Request Smuggling via Fragmentation
            
        1.4.2 DNS Fragmentation Exploits
            1.4.2.1 Fragmented DNS Response Poisoning
            1.4.2.2 DNSSEC Fragment Amplification
            
        1.4.3 VPN Tunnel Fragmentation
            1.4.3.1 IPsec Fragment Reassembly Bypass
            1.4.3.2 SSL/TLS Record Fragmentation Attack
            
    1.5 State Table Manipulation [OR]
    
        1.5.1 NAT State Table Corruption
            1.5.1.1 Fragment-Based State Table Overflow
            1.5.1.2 ASIC Buffer Memory Exhaustion
            
        1.5.2 Load Balancer Persistence Bypass
            1.5.2.1 Fragment-Based Session Affinity bypass
            1.5.2.2 VIP Fragmentation Attack
            
    1.6 Evasion of Deep Packet Inspection [OR]
    
        1.6.1 Signature Avoidance
            1.6.1.1 Payload Split Across Fragment Boundary
            1.6.1.2 Pattern Offset Manipulation
            
        1.6.2 SSL/TLS Inspection Bypass
            1.6.2.1 Certificate Split Across Fragments
            1.6.2.2 Handshake Message Fragmentation
            
        1.6.3 Data Exfiltration
            1.6.3.1 Covert Channel Using Fragment Identification Field
            1.6.3.2 Fragment Timing Channel
            
    1.7 Network Protocol Specific [OR]
    
        1.7.1 TCP Specific Attacks
            1.7.1.1 TCP Segment Overlap Desynchron
            1.7.1.2 SEQ/ACK Number Fragmentation Attack
            
        1.7.2 ICMP Fragmentation
            1.7.2.1 ICMP Parameter Problem with Fragments
            1.7.2.2 ICMP Error Message Amplification
            
        1.7.3 Multicast Fragmentation
            1.7.3.1 IGMP Fragment Flood
            1.7.3.2 PIM Fragment Resource Exhaustion
            
    1.8 Hardware Specific Exploits [OR]
    
        1.8.1 ASIC-Based Router Attacks
            1.8.1.1 Hardware Accelerator Overflow
            1.8.1.2 Ternary Content-Addressable Memory (TCAM) Exhaustion
            
        1.8.2 FPGA Networking Card Exploits
            1.8.2.1 Fragment Reassembly Logic Bomb
            1.8.2.2 DMA Fragment Buffer Overflow
            
        1.8.3 Switch Fabric Attacks
            1.8.3.1 Crossbar Buffer Fragment Flood
            1.8.3.2 Virtual Output Queue (VOQ) Fragmentation Attack
            
    1.9 Cloud and Virtual [OR]
    
        1.9.1 Hypervisor Attacks
            1.9.1.1 Virtual Switch Fragment Reassembly Bypass
            1.9.1.2 VM-to-VM Fragment Attack
            
        1.9.2 Container Network Attacks
            1.9.2.1 Docker Bridge Fragment Flood
            1.9.2.2 Kubernetes CNI Fragment Exhaustion
            
        1.9.3 Cloud Load Balancer Attacks
            1.9.3.1 AWS ALB/NLB Fragment Handling Exploit
            1.9.3.2 Azure Load Balancer Fragment Bypass
            
    1.10 IoT and Embedded Systems [OR]
    
        1.10.1 Limited Resource Exploitation
            1.10.1.1 Memory-Constrained Device Fragment Flood
            1.10.1.2 Real-Time OS Fragment Handling Flaws
            
        1.10.2 Industrial Control Systems (ICS)
            1.10.2.1 SCADA Protocol Fragmentation Attack
            1.10.2.2 Modbus TCP Fragment Desynchron
            
        1.10.3 Automotive Systems
            1.10.3.1 CAN Bus IP Gateway Fragment Attack
            1.10.3.2 Automotive Ethernet Fragmentation Exploit
```

## Why it works

-   Legacy Code & Embedded Systems: Many older operating systems and countless IoT devices run on outdated kernels with known, unpatched fragmentation reassembly vulnerabilities.
-   Performance vs. Security Trade-off: Fully reassembling every packet flow is computationally expensive. Network middleboxes (firewalls, IPS) may skip deep inspection of fragments to maintain throughput, creating a blind spot.
-   Protocol Complexity: The IP specification allows for fragmentation, and handling all edge cases correctly (e.g., non-zero fragment offsets, inconsistent sizes) is difficult, leading to implementation flaws.

## Mitigation

### Patching

-   Action: Establish a rigorous patch management program.
-   How: Subscribe to security mailing lists (e.g., CERT, vendor advisories) for all network devices (routers, firewalls), servers, and IoT device firmware. Prioritize and apply patches for vulnerabilities identified by CVEs related to "IP fragmentation," "Teardrop," or "Ping of Death."
-   Example: Regularly update Linux kernels on servers to incorporate the latest security fixes for the `net/ipv4/ip_fragment.c` module.

### Firewall configuration

-   Action: Configure firewalls to be fragmentation-aware.
-   How:
    -   Cisco ASA/Firepower: Use the `fragment` command to set chain limits and timeouts. Enable settings to "Reassemble before inspection."
    -   iptables (Linux): Use rules to drop suspicious fragments.
        -   `iptables -A INPUT -f -j DROP` drops all fragmented packets (aggressive, may break legitimate traffic).
        -   A more nuanced approach: Use the `u32` module to check for malicious fragment offsets.
    -   Palo Alto Networks: Ensure the security policy has "Decrypt and reassemble fragments for inspection" enabled in the rule's profile.
    -   General Best Practice: Where possible, outright block all fragmented packets at the internet edge. Modern protocols like TCP and HTTP/2 are designed to avoid fragmentation. If fragmentation is necessary for legitimate internal applications, only allow it from trusted sources.

### Kernel hardening

-   Action: Tune operating system parameters to limit the impact of a fragmentation flood.
-   How (Linux Specific):
    -   Reduce Reassembly Buffer Size: Lowering the maximum memory allocated for reassembly makes the system more resilient to exhaustion attacks.
        -   `sysctl -w net.ipv4.ipfrag_high_thresh=262144` (sets a lower maximum memory threshold)
        -   `sysctl -w net.ipv4.ipfrag_time=15` (reduces the time window for reassembling a packet)
    -   Make Changes Permanent: Add these lines to `/etc/sysctl.conf`.
-   Note: Test these changes in a non-production environment first, as they may impact the performance of legitimate applications that rely on fragmentation.

### Intrusion prevention systems (IPS)

-   Action: Deploy and tune IPS signatures specifically for fragmentation attacks.
-   How:
    -   Snort/Suricata: Enable and test rules within categories like `protocol-ip-fragmentation` and `protocol-ip-bad-frags`. Examples include detecting packets with the "More Fragments" flag set but a zero offset, or overlapping fragments.
    -   Commercial IPS (e.g., Sourcefire, Check Point): Ensure the IPS policy is configured to perform "stream reassembly" and has signatures for fragmentation evasion techniques enabled and set to a blocking mode.
    -   Tuning: Regularly review IPS logs for false positives related to fragmentation rules to ensure legitimate traffic is not disrupted.
