# IPv6 Extension header abuse

## Attack pattern

IPv6 Extension Headers (EHs) provide flexibility and new features but introduce significant attack vectors. Attackers exploit EH processing weaknesses to evade security controls, cause resource exhaustion, and bypass filtering mechanisms. The complexity and variability of EH chains create opportunities for evasion and denial-of-service attacks.

```text
1. Extension Header Abuse [OR]

    1.1 Evasion & Bypass Attacks [OR]
    
        1.1.1 Firewall & IDS/IPS Evasion
            1.1.1.1 Splitting malicious payload across multiple EHs
            1.1.1.2 Hiding exploit code in Destination Options headers
            1.1.1.3 Using Hop-by-Hop options to bypass deep inspection
            
        1.1.2 Filtering Bypass
            1.1.2.1 Crafting EH chains that are poorly parsed by security devices
            1.1.2.2 Using unknown or experimental EH types to evade signature detection
            1.1.2.3 Fragmenting EHs to avoid pattern matching
            
    1.2 Resource Exhaustion Attacks [OR]
    
        1.2.1 CPU Exhaustion
            1.2.1.1 Crafting deeply nested EH chains that require complex processing
            1.2.1.2 Using encryption in EHs to increase computational load
            1.2.1.3 Creating packets with multiple routing headers forcing path recomputation
            
        1.2.2 Memory Consumption
            1.2.2.1 Sending packets with extremely large EH options
            1.2.2.2 Creating packet queues with complex EH chains
            1.2.2.3 Exploiting buffer management in EH processing code
            
    1.3 Protocol Manipulation [OR]
    
        1.3.1 Routing Header Type 0 Attacks (RH0 - deprecated but still found)
            1.3.1.1 Creating amplification attacks using RH0
            1.3.1.2 Forcing packets through attacker-controlled nodes
            1.3.1.3 Causing traffic loops and network congestion
            
        1.3.2 Destination Options Abuse
            1.3.2.1 Modifying packet processing behaviour maliciously
            1.3.2.2 Injecting instructions that alter host behaviour
            1.3.2.3 Using options to carry covert channel data
            
    1.4 Fragmentation Abuse [OR]
    
        1.4.1 EH Fragmentation Attacks
            1.4.1.1 Splitting critical EH across multiple fragments
            1.4.1.2 Creating overlapping EH fragments to exploit reassembly bugs
            1.4.1.3 Using fragmentation to hide malicious EH content
            
        1.4.2 Reassembly Resource Exhaustion
            1.4.2.1 Flooding with fragmented EH packets
            1.4.2.2 Creating incomplete EH chains that consume reassembly buffers
            1.4.2.3 Exploiting timeout mechanisms in reassembly processes
            
    1.5 Covert Channels & Data Exfiltration [OR]
    
        1.5.1 Stealth Data Transfer
            1.5.1.1 Embedding data in EH option fields
            1.5.1.2 Using padding options for information hiding
            1.5.1.3 Creating timing channels using EH processing delays
            1.5.1.4 Covert channel via Traffic Class / Flow Label
                1.5.1.4.1 Encoding data in Traffic Class field (DSCP/ECN bits)
                1.5.1.4.2 Storing information in 20-bit Flow Label field
                1.5.1.4.3 Manipulating header fields to create stealth communication
                1.5.1.4.4 Using bit-level encoding in unused header space
            
        1.5.2 Command and Control
            1.5.2.1 Using EHs for C2 communication
            1.5.2.2 Embedding instructions in Hop-by-Hop options
            1.5.2.3 Evading detection by using legitimate-looking EH patterns
            1.5.2.4 Traffic Class/Flow Label C2 channels
                1.5.2.4.1 Using DSCP values as command signals
                1.5.2.4.2 Flow Label modulation for instruction passing
                1.5.2.4.3 Header field manipulation for remote control
            
    1.6 Specific Header Exploitation [OR]
    
        1.6.1 Hop-by-Hop Options Attacks
            1.6.1.1 Using Router Alert option to trigger unnecessary processing
            1.6.1.2 Creating packets that require special processing at every hop
            1.6.1.3 Exploiting Jumbo Payload option to cause buffer overflows
            
        1.6.2 Destination Options Attacks
            1.6.2.1 Using PadN options to hide malicious content
            1.6.2.2 Exploiting option parsing vulnerabilities
            1.6.2.3 Modifying packet processing in malicious ways
            
    1.7 Implementation-Specific Attacks [OR]
    
        1.7.1 Stack Vulnerability Exploitation
            1.7.1.1 Buffer overflows in EH processing code
            1.7.1.2 Integer overflows in option length handling
            1.7.1.3 Memory corruption through malformed option content
            
        1.7.2 Hardware Offload Exploitation
            1.7.2.1 Bypassing hardware acceleration through complex EH chains
            1.7.2.2 Causing ASIC or NPU failures through malformed EHs
            1.7.2.3 Creating packets that fall back to slow-path processing
            
    1.8 Network Reconnaissance [OR]
    
        1.8.1 Path Discovery
            1.8.1.1 Using Routing headers to map network paths
            1.8.1.2 Analysing EH processing to identify middlebox types
            1.8.1.3 Fingerprinting systems based on EH handling behaviour
            
        1.8.2 Service Discovery
            1.8.2.1 Using EHs to probe for specific services
            1.8.2.2 Detecting security devices through EH response patterns
            1.8.2.3 Identifying vulnerable implementations through EH probing
            
    1.9 Amplification & Reflection [OR]
    
        1.9.1 EH-based Amplification
            1.9.1.1 Creating packets that generate large responses
            1.9.1.2 Using Routing headers to create traffic amplification
            1.9.1.3 Exploiting EH processing to consume victim resources
            
        1.9.2 Reflection Attacks
            1.9.2.1 Using spoofed source addresses with complex EHs
            1.9.2.2 Forcing intermediaries to generate error messages
            1.9.2.3 Creating packets that cause multiple responses
            
    1.10 Protocol Interaction Attacks [OR]
    
        1.10.1 EH with IPsec Abuse
            1.10.1.1 Bypassing IPsec protection through EH manipulation
            1.10.1.2 Creating packets that confuse ESP/AH processing
            1.10.1.3 Using EHs to weaken cryptographic protection
            
        1.10.2 EH with Fragment Interaction
            1.10.2.1 Creating reassembly dependencies that exploit EH processing
            1.10.2.2 Using fragmentation to hide malicious EH content
            1.10.2.3 Exploiting fragment reassembly with EHs for evasion
```

## Why it works

-   Complex processing: EHs require substantial processing power, creating opportunities for CPU exhaustion
-   Implementation inconsistencies: Different devices handle EHs differently, leading to security gaps
-   Filtering challenges: Many security devices cannot properly inspect complex EH chains
-   Protocol flexibility: The extensible nature of EHs allows attackers to create novel attack vectors
-   Limited visibility: Monitoring tools often lack deep EH inspection capabilities
