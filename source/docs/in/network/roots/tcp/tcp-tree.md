# Attack tree (TCP)


```text
1. Compromise BGP via TCP Vulnerabilities [OR]

    1.1 Exploit TCP Stack on BGP Router [OR]
    
        1.1.1 Remote Code Execution (RCE) via TCP/IP flaws
            1.1.1.1 Exploit router OS TCP stack (JunOS, IOS XR flaws)
            1.1.1.2 Kernel memory corruption (SACK-based attacks, CVE-2019-11477)
            1.1.1.3 Deploy malicious BGP configurations post-exploit
            
        1.1.2 Denial of Service via TCP [OR]
            1.1.2.1 TCP SACK resource exhaustion
            1.1.2.2 TCP SYN flood to exhaust BGP peer resources
            1.1.2.3 Trigger kernel crashes through crafted TCP packets
            
    1.2 BGP Session Manipulation [OR]
    
        1.2.1 Session Establishment Attacks [OR]
            1.2.1.1 TCP SYN flood attack
            1.2.1.2 Exploit BGP's MD5 authentication weaknesses
            1.2.1.3 Bypass MD5 via TCP session hijacking
            
        1.2.2 Active Session Hijacking [AND]
            1.2.2.1 Predict BGP TCP sequence numbers [OR]
                |-> Off-path ISN prediction using timestamp leaks
                |-> In-window guessing due to poor ISN randomization
            1.2.2.2 Inject malicious BGP updates [OR]
                |-> Spoofed route advertisements
                |-> Crafted AS_PATH manipulation
                |-> Route flap storms (announce/withdraw)
            
        1.2.3 Session Persistence Abuse [OR]
            1.2.3.1 Force BGP session resets via TCP attacks [AND]
                |-> Inject RST packets (precision spoofing)
                |-> Exploit TCP keepalive timeouts
            1.2.3.2 Subvert BGP graceful restart [OR]
                |-> Spoof graceful restart capabilities
                |-> Exhaust router memory during recovery
            
    1.3 Man-in-the-Middle BGP Sessions [AND]
    
        1.3.1 Traffic Interception [OR]
            1.3.1.1 ARP/DNS spoofing to redirect BGP traffic
            1.3.1.2 BGP peering over unencrypted links (IXPs)
            1.3.1.3 On-path position for packet capture
            
        1.3.2 Message Manipulation [OR]
            1.3.2.1 Decrypt or modify BGP messages
            1.3.2.2 Downgrade TCP-MD5 to plaintext (if misconfigured)
            1.3.2.3 Exploit missing TCP-AO (Authentication Option)
            1.3.2.4 Bypass TCP-AO protection [AND]
                |-> Key extraction from compromised router
                |-> Cryptographic weakness exploitation
                |-> Implementation-specific vulnerabilities
            
    1.4 Protocol-Level TCP Attacks [OR]
    
        1.4.1 Connection Hijacking [AND]
            1.4.1.1 Off-path sequence number prediction
            1.4.1.2 Malicious packet injection (RST/FIN spoofing)
            
        1.4.2 Amplification/Reflection Attacks [OR]
            1.4.2.1 TCP middlebox reflection
            1.4.2.2 ACK/PSH flood abuse
            1.4.2.3 BGP update reflection/amplification
            
    1.5 Off-Path & Side-Channel Attacks [AND]
    
        1.5.1 Blind In-Window Exploit [OR]
            1.5.1.1 NAT slipstreaming variants
            1.5.1.2 Protocol downgrade attacks (QUIC-to-TCP)
            
        1.5.2 Side-Channel Data Extraction [OR]
            1.5.2.1 TCP timestamp analysis
            1.5.2.2 Application data correlation
            1.5.2.3 Encrypted traffic classification
            
    1.6 Cloud/Middlebox-Specific Attacks [OR]
    
        1.6.1 Bypass Cloud Load Balancers [AND]
            1.6.1.1 Crafted TCP segmentation evasion
            1.6.1.2 Instance resource exhaustion
            
        1.6.2 Stateful Firewall Evasion [OR]
            1.6.2.1 TCP Fast Open (TFO) cache poisoning
            1.6.2.2 Fragmentation overlap attacks
            1.6.2.3 Evade BGP monitoring systems
            
    1.7 AI/ML-Enhanced TCP Attacks [AND]
    
        1.7.1 Traffic Fingerprinting [OR]
            1.7.1.1 Encrypted traffic classification
            1.7.1.2 SCADA system detection via flow patterns
            1.7.1.3 BGP peer behaviour analysis
            
        1.7.2 Adversarial Traffic Generation [OR]
            1.7.2.1 GAN-based normal traffic modelling
            1.7.2.2 Stealthy DDoS payload synthesis
            1.7.2.3 ML-generated TCP sequence prediction
            
2. Composite BGP/TCP Attack Vectors [OR]

    2.1 BGP + TCP Stack Exploitation [OR]
    
        2.1.1 Router OS Compromise [AND]
            2.1.1.1 TCP stack vulnerability exploitation
            2.1.1.2 Persistent BGP route manipulation
            
        2.1.2 Kernel-Level Attacks [OR]
            2.1.2.1 Memory corruption via crafted TCP options
            2.1.2.2 Resource exhaustion attacks
            2.1.2.3 BGP process isolation bypass
            
    2.2 Session Integrity Attacks [OR]
    
        2.2.1 Cryptographic Weaknesses [OR]
            2.2.1.1 TCP-MD5 hash cracking (weak keys)
            2.2.1.2 TCP-AO hash collision attacks
            2.2.1.3 RPKI certificate chain exploitation
            2.2.1.4 TCP-AO key compromise through side-channels
            2.2.1.5 Algorithm vulnerability exploitation (SHA-1/256)
            
        2.2.2 Protocol Downgrade Attacks [AND]
            2.2.2.1 Force plaintext BGP sessions
            2.2.2.2 Exploit missing authentication
            2.2.2.3 Session negotiation manipulation
            2.2.2.4 TCP-AO fallback mechanism exploitation
            
    2.3 Network Infrastructure Attacks [OR]
    
        2.3.1 IXP and Route Server Targeting [OR]
            2.3.1.1 Compromised IXP route server software
            2.3.1.2 BGP peering link interception
            2.3.1.3 Route reflector compromise
            
        2.3.2 Management Interface Exploitation [OR]
            2.3.2.1 Exposed BGP monitoring systems
            2.3.2.2 Compromised SSH keys for router access
            2.3.2.3 Default credentials on admin interfaces
            2.3.2.4 TCP-AO key material theft through config leaks
            
    2.4 Advanced Persistence Mechanisms [OR]
    
        2.4.1 Stealthy Route Manipulation [OR]
            2.4.1.1 Time-based hijacking (short-lived attacks)
            2.4.1.2 Geographic-specific route manipulation
            2.4.1.3 Mimicking legitimate AS-path patterns
            
        2.4.2 Detection Evasion [OR]
            2.4.2.1 Abuse of RPKI 'unknown' state
            2.4.2.2 Leveraging peer conflicts for ambiguity
            2.4.2.3 Adaptive attack timing based on network monitoring
            
3. Cross-Protocol Attack Chains [OR]

    3.1 Multi-Vector BGP/TCP Compromise [OR]
    
        3.1.1 Chained Exploitation [AND]
            3.1.1.1 Initial access via TCP stack vulnerability
            3.1.1.2 Privilege escalation to BGP process
            3.1.1.3 Persistent route manipulation
            3.1.1.4 TCP-AO key material extraction
            
        3.1.2 Coordinated Attacks [OR]
            3.1.2.1 Distributed TCP sequence prediction
            3.1.2.2 Synchronized BGP session reset attacks
            3.1.2.3 Cross-platform exploitation campaigns
            
    3.2 AI-Powered TCP/BGP Attacks [OR]
    
        3.2.1 ML-Generated Attack Traffic
        3.2.2 Autonomous hijack coordination
        3.2.3 Adaptive persistence mechanisms
        3.2.4 Evolutionary path optimization
        3.2.5 AI-enhanced TCP-AO cryptographic attacks
        
    3.3 Supply Chain Compromise [OR]
    
        3.3.1 Backdoored router firmware/images
        3.3.2 Malicious BGP optimization tools
        3.3.3 Compromised network management software
        3.3.4 Pre-installed weak TCP-AO keys in vendor equipment
```