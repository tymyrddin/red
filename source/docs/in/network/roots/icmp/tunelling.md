# ICMP tunnelling for data exfiltration & covert channels

## Attack pattern

ICMP tunnelling represents a sophisticated data exfiltration technique that abuses the Internet Control Message 
Protocol to create covert communication channels. This method enables attackers to bypass traditional security 
controls by embedding data within seemingly legitimate ICMP traffic, making detection challenging while maintaining 
bidirectional communication capabilities.

```text
1. ICMP tunnelling [AND]

    1.1 Payload encoding techniques [OR]
    
        1.1.1 ICMP echo payload data encoding
            1.1.1.1 Direct data embedding in echo request/reply payloads
            1.1.1.2 Base64 encoding within ICMP data fields
            1.1.1.3 Fragmented data transmission across multiple ICMP packets
            1.1.1.4 Protocol simulation within ICMP payloads (HTTP/DNS mimicry)
            
        1.1.2 ICMPv6 option field exploitation
            1.1.2.1 Destination options header abuse for data carriage
            1.1.2.2 Hop-by-hop options manipulation for covert data
            1.1.2.3 Extension header chaining for multi-packet data transmission
            1.1.2.4 IPv6 mobility header exploitation for mobile exfiltration
            
        1.1.3 Checksum manipulation for data carrying
            1.1.3.1 Intentional checksum miscalculation for data encoding
            1.1.3.2 Checksum field data storage techniques
            1.1.3.3 Valid checksum maintenance while carrying covert data
            1.1.3.4 Checksum-based error detection evasion
            
    1.2 Tool-based tunnelling [OR]
    
        1.2.1 Icmptunnel IPv6-enabled tunnelling
            1.2.1.1 Dual-stack IPv4/IPv6 tunnelling capabilities
            1.2.1.2 Ethernet frame encapsulation over ICMP
            1.2.1.3 IPv6 extension header support for enhanced stealth
            1.2.1.4 Multi-protocol tunnelling through ICMP encapsulation
            
        1.2.2 Ptunnel advanced ICMP tunnelling
            1.2.2.1 Proxy-based ICMP tunnelling architecture
            1.2.2.2 Encryption support for payload protection
            1.2.2.3 Connection persistence mechanisms
            1.2.2.4 Adaptive timing to evade detection systems
            
        1.2.3 Custom ICMP proxy development
            1.2.3.1 Bespoke tunnelling solutions for specific environments
            1.2.3.2 Protocol-specific adaptation for target networks
            1.2.3.3 Lightweight agents for resource-constrained devices
            1.2.3.4 Multi-format payload support for diverse data types
            
    1.3 Evasion mechanisms [OR]
    
        1.3.1 Traffic shaping to mimic legitimate ICMP
            1.3.1.1 Rate limiting to match normal ICMP traffic patterns
            1.3.1.2 Size variation to resemble legitimate ping traffic
            1.3.1.3 Timing randomisation to avoid pattern detection
            1.3.1.4 Protocol compliance testing to ensure packet validity
            
        1.3.2 Multiple tunnel endpoint rotation
            1.3.2.1 Dynamic C2 server rotation for resilience
            1.3.2.2 Domain generation algorithms for endpoint discovery
            1.3.2.3 Fast-flux DNS techniques for infrastructure hiding
            1.3.2.4 Cloud-based endpoint hopping for scalability
            
        1.3.3 Encrypted payload encapsulation
            1.3.3.1 AES-256 encryption for payload protection
            1.3.3.2 Steganographic techniques within ICMP packets
            1.3.3.3 One-time pad implementation for perfect secrecy
            1.3.3.4 Key exchange through covert channel within ICMP
            
    1.4 Protocol manipulation techniques [OR]
    
        1.4.1 ICMP type and code abuse
            1.4.1.1 Uncommon ICMP types for covert communication
            1.4.1.2 Reserved field exploitation for data storage
            1.4.1.3 Type manipulation to evade signature detection
            1.4.1.4 Code field utilisation for command and control
            
        1.4.2 Fragmentation and reassembly abuse
            1.4.2.1 IP fragmentation for data segmentation
            1.4.2.2 Fragment overlap techniques for evasion
            1.4.2.3 Maximum transmission unit manipulation
            1.4.2.4 Reassembly timeout exploitation for data storage
            
    1.5 Network adaptation strategies [OR]
    
        1.5.1 Environment-aware tunnelling
            1.5.1.1 Automatic protocol selection based on network configuration
            1.5.1.2 Firewall rule detection and adaptation
            1.5.1.3 IDS/IPS evasion through protocol analysis
            1.5.1.4 Network policy reconnaissance and adaptation
            
        1.5.2 Quality of service manipulation
            1.5.2.1 DSCP field manipulation for priority treatment
            1.5.2.2 Traffic class abuse in IPv6 environments
            1.5.2.3 Flow label exploitation for stealth communication
            1.5.2.4 Network congestion avoidance techniques
            
    1.6 Persistence and reliability mechanisms [OR]
    
        1.6.1 Connection recovery techniques
            1.6.1.1 Automatic reconnection mechanisms
            1.6.1.2 Session persistence across network changes
            1.6.1.3 Data integrity verification and retransmission
            1.6.1.4 Heartbeat monitoring for tunnel health
            
        1.6.2 Anti-forensic measures
            1.6.2.1 Log evasion through legitimate-looking traffic
            1.6.2.2 Memory-only operation to avoid disk forensics
            1.6.2.3 Timestamp manipulation to obscure activity
            1.6.2.4 Clean-up operations to remove evidence
```

## Why it works

-   Protocol necessity: ICMP is essential for network operation and cannot be completely blocked
-   Monitoring gaps: Many security systems focus on TCP/UDP while overlooking ICMP traffic
-   Legitimate appearance: ICMP tunnelling traffic mimics normal network operations
-   Encryption capabilities: Modern tools can encrypt payloads, preventing content inspection
-   Protocol flexibility: ICMP's simple structure allows for various data encoding methods
-   Network pervasiveness: ICMP traffic is common in most networks, providing cover
