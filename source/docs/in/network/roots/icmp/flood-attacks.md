# ICMP flood attacks

## Attack pattern

ICMP flood attacks represent a category of denial-of-service techniques that leverage the Internet Control Message 
Protocol to overwhelm target systems, networks, or infrastructure components. These attacks exploit the fundamental 
nature of ICMP as a required protocol for network operations, making complete mitigation challenging while allowing 
attackers to cause significant service disruption through various amplification and reflection techniques.

```text
1. ICMP floods [OR]

    1.1 Direct flood attacks [OR]
    
        1.1.1 IPv6 ping6 high-volume floods
            1.1.1.1 High-rate echo request bombardment
            1.1.1.2 Large payload ping6 packets for bandwidth consumption
            1.1.1.3 Dual-stack targeting through IPv6-specific floods
            1.1.1.4 Path MTU discovery exhaustion through oversized packets
            
        1.1.2 ICMPv6 parameter problem floods
            1.1.2.1 Malformed packet generation to trigger error responses
            1.1.2.2 Header corruption attacks forcing parameter problem messages
            1.1.2.3 Extension header manipulation for error induction
            1.1.2.4 Checksum violation attacks to generate error storms
            
        1.1.3 Multicast listener report floods
            1.1.3.1 MLD report message bombardment
            1.1.3.2 Multicast group join storms for router exhaustion
            1.1.3.3 MLD query amplification attacks
            1.1.3.4 Multicast state table exhaustion through rapid group changes
            
    1.2 Spoofed-source attacks [OR]
    
        1.2.1 ICMPv6 spoofed-source floods
            1.2.1.1 Source address spoofing for attribution evasion
            1.2.1.2 Amplification through error message generation
            1.2.1.3 Reflection attack setup through spoofed requests
            1.2.1.4 Botnet coordination with spoofed source addresses
            
        1.2.2 Reflection through compromised infrastructure
            1.2.2.1 Cloud instance abuse for reflection attacks
            1.2.2.2 Compromised network device exploitation
            1.2.2.3 IoT device recruitment for distributed reflection
            1.2.2.4 Public service abuse for amplified attacks
            
        1.2.3 Botnet-based distributed flooding
            1.2.3.1 IoT botnet mobilisation for ICMP floods
            1.2.3.2 Mobile device network participation
            1.2.3.3 Cloud resource compromise for attack scaling
            1.2.3.4 Coordinated attack timing for maximum impact
            
    1.3 Protocol-specific floods [OR]
    
        1.3.1 Neighbour solicitation storms
            1.3.1.1 NS message bombardment for cache exhaustion
            1.3.1.2 Address resolution flood attacks
            1.3.1.3 DAD (Duplicate Address Detection) process abuse
            1.3.1.4 Neighbour cache table exhaustion attacks
            
        1.3.2 Router advertisement flooding
            1.3.2.1 RA message storms for host configuration disruption
            1.3.2.2 Default router list exhaustion attacks
            1.3.2.3 Prefix information flood for address assignment disruption
            1.3.2.4 Parameter spoofing through malicious RAs
            
        1.3.3 MLD report exhaustion attacks
            1.3.3.1 Multicast listener report storms
            1.3.3.2 Group membership flood attacks
            1.3.3.3 Router state table exhaustion through rapid reports
            1.3.3.4 Query interval manipulation for amplified effects
            
    1.4 Amplification techniques [OR]
    
        1.4.1 Error message amplification
            1.4.1.1 Parameter problem message amplification
            1.4.1.2 Destination unreachable message exploitation
            1.4.1.3 Time exceeded amplification attacks
            1.4.1.4 Packet too big message exploitation
            
        1.4.2 Multicast amplification
            1.4.2.1 Multicast group amplification techniques
            1.4.2.2 MLD query amplification attacks
            1.4.2.3 Multicast router reflection attacks
            1.4.2.4 Scope-based amplification exploitation
            
    1.5 Resource exhaustion attacks [OR]
    
        1.5.1 CPU exhaustion through processing demands
            1.5.1.1 Complex ICMPv6 message processing attacks
            1.5.1.2 Extension header processing exhaustion
            1.5.1.3 Checksum verification load attacks
            1.5.1.4 State table maintenance exhaustion
            
        1.5.2 Memory consumption attacks
            1.5.2.1 Buffer allocation exhaustion through packet floods
            1.5.2.2 Neighbour cache memory exhaustion
            1.5.2.3 Routing table memory depletion
            1.5.2.4 Packet reassembly buffer exhaustion
            
    1.6 Network infrastructure targeting [OR]
    
        1.6.1 Router-specific attacks
            1.6.1.1 Control plane policing bypass attacks
            1.6.1.2 Routing protocol disruption through ICMP floods
            1.6.1.3 Forwarding plane exhaustion attacks
            1.6.1.4 Management interface targeting
            
        1.6.2 Firewall and security device targeting
            1.6.2.1 State table exhaustion through ICMP variations
            1.6.2.2 Deep packet inspection bypass through floods
            1.6.2.3 Rule processing exhaustion attacks
            1.6.2.4 Logging system overload through attack volume
```

## Why it works

-   Protocol necessity: ICMP is essential for network operations and cannot be completely blocked without affecting functionality
-   Amplification potential: Certain ICMP messages can generate larger responses, creating amplification opportunities
-   Resource asymmetry: Attackers can leverage distributed resources that overwhelm target capacity
-   Spoofing capabilities: Source address spoofing makes attribution and blocking difficult
-   Protocol complexity: ICMPv6's additional features create more attack vectors than ICMPv4
-   Default configurations: Many systems process ICMP packets by default without rate limiting
