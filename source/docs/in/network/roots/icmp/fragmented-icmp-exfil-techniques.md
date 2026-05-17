# Fragmented ICMP exfiltration techniques

## Attack pattern

Fragmented ICMP exfiltration represents a sophisticated data extraction methodology that abuses IP fragmentation 
mechanisms to bypass security controls. This technique enables attackers to distribute payloads across multiple 
ICMP packets, evading detection systems that may not properly reassemble or inspect fragmented traffic while 
maintaining covert communication channels.

```text
2. Fragmented ICMP exfiltration [OR]

    2.1 IPv6 fragmentation abuse [OR]
    
        2.1.1 IPv6 jumbogram exploitation
            2.1.1.1 Jumbo payload option manipulation for large data transfer
            2.1.1.2 Maximum packet size evasion through jumbogram support
            2.1.1.3 Router compatibility testing for jumbogram support
            2.1.1.4 Path MTU discovery integration with jumbogram usage
            
        2.1.2 Fragment header manipulation
            2.1.2.1 Fragment extension header abuse for data carriage
            2.1.2.2 Fragment offset manipulation for payload distribution
            2.1.2.3 More fragments flag exploitation for multi-packet transmission
            2.1.2.4 Identification field manipulation for session tracking
            
        2.1.3 DPI evasion through fragment reassembly
            2.1.3.1 Deep packet inspection bypass via fragmented transmission
            2.1.3.2 Signature evasion through payload splitting
            2.1.3.3 Content inspection avoidance via fragment distribution
            2.1.3.4 Protocol analysis confusion through fragmented ICMP
            
    2.2 Payload distribution techniques [OR]
    
        2.2.1 Split payloads across multiple ICMP packets
            2.2.1.1 Data chunking algorithms for optimal fragment distribution
            2.2.1.2 Sequence numbering for fragment reassembly
            2.2.1.3 Error correction coding for fragment recovery
            2.2.1.4 Checksum validation across fragmented payloads
            
        2.2.2 Time-distributed fragment transmission
            2.2.2.1 Temporal spacing to evade rate-based detection
            2.2.2.2 Randomised transmission timing for pattern avoidance
            2.2.2.3 Burst transmission during high network activity
            2.2.2.4 Low-and-slow fragment delivery techniques
            
        2.2.3 Geographic fragment distribution
            2.2.3.1 Multi-region fragment transmission for attribution protection
            2.2.3.2 Content delivery network abuse for fragment distribution
            2.2.3.3 Cloud service exploitation for geographic diversity
            2.2.3.4 Tor network utilisation for anonymous fragment routing
            
    2.3 Stealth fragmentation [OR]
    
        2.3.1 Legitimate-looking fragment patterns
            2.3.1.1 MTU-compliant fragment size selection
            2.3.1.2 Common fragment size mimicry for blending
            2.3.1.3 Network-appropriate fragment pattern adoption
            2.3.1.4 Protocol-compliant fragment flag configuration
            
        2.3.2 MTU discovery integration
            2.3.2.1 Path MTU discovery for optimal fragment sizing
            2.3.2.2 Black hole detection and avoidance techniques
            2.3.2.3 MTU probing for network characteristic analysis
            2.3.2.4 Dynamic fragment size adjustment based on MTU
            
        2.3.3 ICMP error message fragmentation
            2.3.3.1 Fragmented ICMP error message exploitation
            2.3.3.2 Time exceeded message fragmentation abuse
            2.3.3.3 Destination unreachable message fragmentation
            2.3.3.4 Parameter problem message fragmentation techniques
            
    2.4 Reassembly mechanism exploitation [OR]
    
        2.4.1 Fragment timeout manipulation
            2.4.1.1 Reassembly timer exploitation for delayed extraction
            2.4.1.2 Timeout-based evasion of security controls
            2.4.1.3 Staggered fragment delivery to exceed timeouts
            2.4.1.4 Buffer exhaustion through prolonged reassembly
            
        2.4.2 Fragment overlap attacks
            2.4.2.1 Overlapping fragment exploitation for data obfuscation
            2.4.2.2 TCP fragment overlap techniques adapted for ICMP
            2.4.2.3 Offset manipulation for payload concealment
            2.4.2.4 Reassembly ambiguity creation for evasion
            
    2.5 Network condition exploitation [OR]
    
        2.5.1 Congestion-based fragmentation
            2.5.1.1 Network congestion exploitation for fragment blending
            2.5.1.2 Quality of service manipulation for fragment priority
            2.5.1.3 Traffic shaping integration for natural fragment appearance
            2.5.1.4 Bufferbloat conditions exploitation
            
        2.5.2 Wireless network fragmentation
            2.5.2.1 MTU variation exploitation in wireless environments
            2.5.2.2 Signal strength-based fragment size adjustment
            2.5.2.3 Mobile network handover exploitation for fragment distribution
            2.5.2.4 5G network slicing abuse for fragment transmission
```

## Why it works

-   Fragmentation necessity: IP fragmentation is required for proper network operation and cannot be completely disabled
-   Reassembly complexity: Many security systems lack robust fragment reassembly capabilities
-   Performance considerations: Full fragment reassembly for inspection is computationally expensive
-   Protocol compliance: Fragmented traffic appears legitimate and follows RFC standards
-   Monitoring gaps: Fragment-based detection often has high false positive rates
-   Network diversity: Different networks handle fragmentation differently, creating exploitation opportunities
