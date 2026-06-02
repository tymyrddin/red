# Lateral movement via ICMP

## Attack pattern

Lateral movement via ICMP represents a sophisticated attack methodology where threat actors utilise the Internet Control Message Protocol to navigate through network environments after initial compromise. These techniques enable advanced persistent threats to maintain stealth, evade detection, and propagate across systems while leveraging seemingly legitimate network traffic.

```text
1. Lateral movement via ICMP [OR]

    1.1 Advanced persistent threat techniques [OR]
    
        1.1.1 APT29-style internal C2 channels
            1.1.1.1 Covert ICMP-based command and control
            1.1.1.2 Data exfiltration through ICMP timing channels
            1.1.1.3 Host discovery using ICMP echo manipulation
            1.1.1.4 Persistence maintenance through regular ICMP beacons
            
        1.1.2 APT41 ICMP-based lateral movement
            1.1.2.1 Network mapping through ICMP sweep techniques
            1.1.2.2 System fingerprinting via ICMP response analysis
            1.1.2.3 Privilege escalation using ICMP trigger mechanisms
            1.1.2.4 Lateral movement coordination through ICMP signals
            
        1.1.3 Equation group ICMP tradecraft
            1.1.3.1 Sophisticated ICMP tunnel construction
            1.1.3.2 Protocol-level manipulation for evasion
            1.1.3.3 Long-term persistence using ICMP backdoors
            1.1.3.4 Anti-forensic techniques through ICMP pattern masking
            
    1.2 Authentication abuse [OR]
    
        1.2.1 ICMP-based password spraying
            1.2.1.1 Credential attack timing through ICMP response analysis
            1.2.1.2 Authentication service discovery via ICMP probing
            1.2.1.3 Account lockout avoidance using ICMP-based timing
            1.2.1.4 Domain controller identification through ICMP patterns
            
        1.2.2 Network service discovery via ICMP
            1.2.2.1 Service enumeration through ICMP error messages
            1.2.2.2 Port scanning using ICMP-based techniques
            1.2.2.3 Application fingerprinting via ICMP response analysis
            1.2.2.4 Database service discovery through ICMP manipulation
            
        1.2.3 Trust relationship exploitation
            1.2.3.1 Domain trust discovery using ICMP-based techniques
            1.2.3.2 Cross-domain movement facilitation through ICMP
            1.2.3.3 Forest trust enumeration via ICMP analysis
            1.2.3.4 Kerberos realm discovery through ICMP patterns
            
    1.3 Container/cloud lateral movement [OR]
    
        1.3.1 Kubernetes pod-to-pod ICMP tunnels
            1.3.1.1 Container network namespace traversal
            1.3.1.2 Service mesh bypass using ICMP communication
            1.3.1.3 Cluster internal movement through ICMP channels
            1.3.1.4 Network policy evasion via ICMP protocol abuse
            
        1.3.2 Cloud VPC ICMP-based traversal
            1.3.2.1 Virtual private cloud lateral movement
            1.3.2.2 Security group rule exploitation through ICMP
            1.3.2.3 Cross-account movement using ICMP techniques
            1.3.2.4 Region-to-region traversal via ICMP communication
            
        1.3.3 Serverless function ICMP communication
            1.3.3.1 Function-to-function ICMP-based coordination
            1.3.3.2 Cold start exploitation through ICMP triggers
            1.3.3.3 Event-driven lateral movement using ICMP
            1.3.3.4 Cloud provider integration abuse via ICMP
            
    1.4 Network segmentation evasion [OR]
    
        1.4.1 VLAN hopping via ICMP manipulation
            1.4.1.1 Switch security control bypass
            1.4.1.2 Virtual LAN traversal techniques
            1.4.1.3 Trunking protocol exploitation through ICMP
            1.4.1.4 Private VLAN circumvention
            
        1.4.2 Firewall rule abuse
            1.4.2.1 ACL bypass through ICMP protocol necessity
            1.4.2.2 Stateful firewall evasion techniques
            1.4.2.3 Application layer gateway bypass
            1.4.2.4 Deep packet inspection evasion
            
    1.5 Persistence mechanisms [OR]
    
        1.5.1 ICMP-based persistence techniques
            1.5.1.1 Regular beaconing for connection maintenance
            1.5.1.2 Dead drop resolvers using ICMP
            1.5.1.3 Connection recovery through ICMP triggers
            1.5.1.4 Persistence verification via ICMP response analysis
            
        1.5.2 Evasion and stealth techniques
            1.5.2.1 Traffic pattern mimicry for detection avoidance
            1.5.2.2 Rate limiting compliance for stealth operations
            1.5.2.3 Legitimate service imitation through ICMP
            1.5.2.4 Forensic evidence avoidance methods
            
    1.6 Command and control integration [OR]
    
        1.6.1 ICMP-based C2 infrastructure
            1.6.1.1 Distributed C2 channel establishment
            1.6.1.2 Fallback mechanism implementation
            1.6.1.3 Redundant communication pathways
            1.6.1.4 Adaptive C2 protocol selection
            
        1.6.2 Data exfiltration techniques
            1.6.2.1 Steganographic data embedding in ICMP packets
            1.6.2.2 Timing channel exploitation for data transfer
            1.6.2.3 Fragment-based data reconstruction
            1.6.2.4 Encryption and obfuscation methods
```

## Why it works

-   Protocol necessity: ICMP is essential for network operations and cannot be completely blocked
-   Monitoring gaps: Many security tools focus on TCP/UDP traffic while overlooking ICMP
-   Stealth capabilities: ICMP traffic appears legitimate and blends with normal network operations
-   Network pervasiveness: ICMP is ubiquitous across all network environments
-   Evasion effectiveness: ICMP-based movement often bypasses traditional security controls
-   Protocol flexibility: ICMP's simple structure allows for various covert communication methods

## Counter moves

Lateral movement via ICMP is the variant in play. Filtering and rate-limiting ICMP, and watching for tunnelling, are the counters. The defender's view is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
