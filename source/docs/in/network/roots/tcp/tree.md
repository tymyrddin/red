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
            3.1.2.2 Synchronised BGP session reset attacks
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

## Nitty gritty risk table

| Attack Path                                                           | Technical Complexity | Resources Required | Risk Level | Notes                                                                                      |
|-----------------------------------------------------------------------|----------------------|--------------------|------------|--------------------------------------------------------------------------------------------|
| 1.1.1.1 Exploit router OS TCP stack (JunOS, IOS XR flaws)             | High                 | Medium             | High       | Requires knowledge of specific vendor vulnerabilities; can lead to full device compromise. |
| 1.1.1.2 Kernel memory corruption (SACK-based attacks, CVE-2019-11477) | High                 | Low                | High       | Exploits known vulnerabilities in TCP SACK processing; can cause RCE or DoS.               |
| 1.1.1.3 Deploy malicious BGP configurations post-exploit              | Medium               | Low                | High       | After initial access, modifies BGP settings to manipulate routing.                         |
| 1.1.2.1 TCP SACK resource exhaustion                                  | Medium               | Low                | Medium     | Consumes router resources through crafted SACK packets; can lead to DoS.                   |
| 1.1.2.2 TCP SYN flood to exhaust BGP peer resources                   | Low                  | High               | High       | Floods BGP peers with SYN packets; disrupts session establishment.                         |
| 1.1.2.3 Trigger kernel crashes through crafted TCP packets            | High                 | Low                | High       | Sends malformed TCP packets to crash the kernel; causes service disruption.                |
| 1.2.1.1 TCP SYN flood attack                                          | Low                  | High               | Medium     | Basic DoS attack against BGP session establishment; easily detectable.                     |
| 1.2.1.2 Exploit BGP's MD5 authentication weaknesses                   | Medium               | Low                | High       | Weak MD5 keys or implementations can be cracked or bypassed.                               |
| 1.2.1.3 Bypass MD5 via TCP session hijacking                          | High                 | Medium             | High       | Hijacks TCP session to avoid MD5 authentication; requires sequence prediction.             |
| 1.2.2.1 Predict BGP TCP sequence numbers                              | High                 | Low                | High       | Predicts sequence numbers to inject malicious packets; off-path or in-window.              |
| 1.2.2.2 Inject malicious BGP updates                                  | Medium               | Low                | Very High  | Injects fraudulent routes, AS_PATH manipulations, or route flaps to disrupt routing.       |
| 1.2.3.1 Force BGP session resets via TCP attacks                      | Medium               | Low                | High       | Injects RST packets or exploits timeouts to drop BGP sessions.                             |
| 1.2.3.2 Subvert BGP graceful restart                                  | High                 | Low                | High       | Spoofs graceful restart or exhausts memory during recovery to cause prolonged outages.     |
| 1.3.1.1 ARP/DNS spoofing to redirect BGP traffic                      | Medium               | Low                | High       | Redirects BGP traffic to attacker-in-the-middle; requires local network access.            |
| 1.3.1.2 BGP peering over unencrypted links (IXPs)                     | Low                  | Low                | High       | Eavesdrops on unencrypted BGP sessions at exchange points; easy interception.              |
| 1.3.1.3 On-path position for packet capture                           | High                 | Medium             | Very High  | Attacker positioned on network path can capture and manipulate BGP traffic.                |
| 1.3.2.1 Decrypt or modify BGP messages                                | Very High            | High               | Very High  | Decrypts BGP messages if encryption is weak or compromised; alters routing updates.        |
| 1.3.2.2 Downgrade TCP-MD5 to plaintext                                | Medium               | Low                | High       | Forces fallback to unencrypted sessions if misconfigured.                                  |
| 1.3.2.3 Exploit missing TCP-AO                                        | Medium               | Low                | High       | Targets sessions without TCP-AO authentication; easier to manipulate.                      |
| 1.3.2.4 Bypass TCP-AO protection                                      | Very High            | High               | Very High  | Extracts keys, exploits crypto weaknesses, or implementation flaws to bypass TCP-AO.       |
| 1.4.1.1 Off-path sequence number prediction                           | High                 | Low                | High       | Predicts TCP sequence numbers without being on-path; requires timing or leaks.             |
| 1.4.1.2 Malicious packet injection (RST/FIN spoofing)                 | Medium               | Low                | Medium     | Injects RST or FIN packets to disrupt connections; can be used against BGP sessions.       |
| 1.4.2.1 TCP middlebox reflection                                      | High                 | Medium             | High       | Uses middleboxes to reflect and amplify TCP traffic; can target BGP peers.                 |
| 1.4.2.2 ACK/PSH flood abuse                                           | Medium               | High               | Medium     | Floods with ACK or PSH packets to consume resources; may impact BGP performance.           |
| 1.4.2.3 BGP update reflection/amplification                           | High                 | Medium             | High       | Reflects and amplifies BGP updates to overwhelm peers or fabricate routes.                 |
| 1.5.1.1 NAT slipstreaming variants                                    | High                 | Low                | High       | Exploits NAT devices to inject packets; can be used to manipulate BGP sessions.            |
| 1.5.1.2 Protocol downgrade attacks (QUIC-to-TCP)                      | High                 | Low                | Medium     | Forces downgrade to TCP to exploit vulnerabilities; less common for BGP.                   |
| 1.5.2.1 TCP timestamp analysis                                        | Medium               | Low                | Medium     | Analyses timestamps to infer information about hosts or networks.                          |
| 1.5.2.2 Application data correlation                                  | High                 | Low                | Medium     | Correlates TCP data with BGP applications to identify vulnerabilities.                     |
| 1.5.2.3 Encrypted traffic classification                              | High                 | Medium             | Medium     | Uses ML to classify encrypted BGP traffic; reconnaissance for further attacks.             |
| 1.6.1.1 Crafted TCP segmentation evasion                              | High                 | Low                | High       | Evades cloud load balancers using TCP segmentation tricks; can target BGP speakers.        |
| 1.6.1.2 Instance resource exhaustion                                  | Medium               | High               | High       | Exhausts resources of cloud instances hosting BGP; causes DoS.                             |
| 1.6.2.1 TCP Fast Open (TFO) cache poisoning                           | High                 | Low                | High       | Poisons TFO caches to bypass security or inject packets into BGP sessions.                 |
| 1.6.2.2 Fragmentation overlap attacks                                 | High                 | Low                | High       | Uses overlapping fragments to evade firewalls or IDS; can target BGP.                      |
| 1.6.2.3 Evade BGP monitoring systems                                  | High                 | Low                | High       | Uses evasion techniques to avoid detection by BGP monitoring tools.                        |
| 1.7.1.1 Encrypted traffic classification                              | Very High            | High               | Medium     | AI classifies encrypted BGP traffic for reconnaissance or targeting.                       |
| 1.7.1.2 SCADA system detection via flow patterns                      | Very High            | High               | High       | Identifies SCADA systems using BGP for critical infrastructure targeting.                  |
| 1.7.1.3 BGP peer behaviour analysis                                   | Very High            | High               | High       | AI analyses BGP peer behavior to identify weaknesses or opportunities for attack.          |
| 1.7.2.1 GAN-based normal traffic modelling                            | Very High            | High               | Very High  | Generates realistic traffic to evade detection during BGP attacks.                         |
| 1.7.2.2 Stealthy DDoS payload synthesis                               | Very High            | High               | Very High  | AI creates DDoS payloads that mimic legitimate BGP traffic for stealthy attacks.           |
| 1.7.2.3 ML-generated TCP sequence prediction                          | Very High            | High               | Very High  | AI predicts TCP sequences for precise injection into BGP sessions.                         |
| 2.1.1.1 TCP stack vulnerability exploitation                          | High                 | Medium             | High       | Combines TCP exploits with BGP manipulation for persistent access.                         |
| 2.1.1.2 Persistent BGP route manipulation                             | Medium               | Low                | Very High  | After compromising OS, modifies BGP routes for long-term control.                          |
| 2.1.2.1 Memory corruption via crafted TCP options                     | Very High            | Low                | High       | Uses TCP options to corrupt memory and compromise BGP processes.                           |
| 2.1.2.2 Resource exhaustion attacks                                   | Medium               | High               | High       | Exhausts kernel resources to disrupt BGP operations.                                       |
| 2.1.2.3 BGP process isolation bypass                                  | High                 | Low                | High       | Escapes process isolation to manipulate BGP directly from kernel.                          |
| 2.2.1.1 TCP-MD5 hash cracking (weak keys)                             | Medium               | Low                | High       | Cracks weak MD5 keys used in BGP authentication.                                           |
| 2.2.1.2 TCP-AO hash collision attacks                                 | Very High            | High               | Very High  | Exploits hash collisions in TCP-AO to bypass authentication.                               |
| 2.2.1.3 RPKI certificate chain exploitation                           | High                 | Medium             | High       | Compromises RPKI certificates to validate fraudulent BGP routes.                           |
| 2.2.1.4 TCP-AO key compromise through side-channels                   | Very High            | High               | Very High  | Uses side-channels to extract TCP-AO keys from compromised routers.                        |
| 2.2.1.5 Algorithm vulnerability exploitation (SHA-1/256)              | Very High            | High               | Very High  | Exploits weaknesses in SHA-1 or SHA-256 used in BGP security.                              |
| 2.2.2.1 Force plaintext BGP sessions                                  | Medium               | Low                | High       | Downgrades sessions to plaintext to eavesdrop or manipulate.                               |
| 2.2.2.2 Exploit missing authentication                                | Low                  | Low                | Medium     | Targets BGP sessions with no authentication; easy to manipulate.                           |
| 2.2.2.3 Session negotiation manipulation                              | High                 | Low                | High       | Manipulates session setup to weaken security or force vulnerabilities.                     |
| 2.2.2.4 TCP-AO fallback mechanism exploitation                        | High                 | Low                | High       | Exploits fallback mechanisms to bypass TCP-AO authentication.                              |
| 2.3.1.1 Compromised IXP route server software                         | High                 | Medium             | Very High  | Compromises software at IXPs to manipulate routing for multiple networks.                  |
| 2.3.1.2 BGP peering link interception                                 | High                 | Medium             | Very High  | Intercepts peering links at IXPs to manipulate or eavesdrop on BGP.                        |
| 2.3.1.3 Route reflector compromise                                    | High                 | Medium             | Very High  | Compromises route reflectors to inject malicious routes into large networks.               |
| 2.3.2.1 Exposed BGP monitoring systems                                | Low                  | Low                | Medium     | Accesses exposed monitoring systems to gather intelligence or disrupt operations.          |
| 2.3.2.2 Compromised SSH keys for router access                        | Medium               | Low                | High       | Uses stolen SSH keys to access and manipulate BGP routers.                                 |
| 2.3.2.3 Default credentials on admin interfaces                       | Low                  | Low                | High       | Uses default credentials to gain access to router management interfaces.                   |
| 2.3.2.4 TCP-AO key material theft through config leaks                | Medium               | Low                | High       | Steals TCP-AO keys from leaked configuration files or backups.                             |
| 2.4.1.1 Time-based hijacking (short-lived attacks)                    | High                 | Low                | High       | Announces fraudulent routes for short periods to avoid detection.                          |
| 2.4.1.2 Geographic-specific route manipulation                        | High                 | Low                | High       | Targets specific regions with route manipulations to localize impact.                      |
| 2.4.1.3 Mimicking legitimate AS-path patterns                         | High                 | Low                | High       | Copies legitimate AS-paths to make fraudulent routes appear valid.                         |
| 2.4.2.1 Abuse of RPKI 'unknown' state                                 | Medium               | Low                | Medium     | Exploits routes with unknown RPKI validation status to bypass checks.                      |
| 2.4.2.2 Leveraging peer conflicts for ambiguity                       | High                 | Low                | High       | Creates conflicting route advertisements to confuse networks and evade detection.          |
| 2.4.2.3 Adaptive attack timing based on network monitoring            | Very High            | Low                | Very High  | Times attacks to avoid monitoring periods or response teams.                               |
| 3.1.1.1 Initial access via TCP stack vulnerability                    | High                 | Medium             | High       | Uses TCP vulnerabilities to gain initial access to BGP routers.                            |
| 3.1.1.2 Privilege escalation to BGP process                           | High                 | Low                | High       | Escalates privileges to manipulate BGP processes directly.                                 |
| 3.1.1.3 Persistent route manipulation                                 | Medium               | Low                | Very High  | Modifies BGP routes for long-term control or traffic diversion.                            |
| 3.1.1.4 TCP-AO key material extraction                                | Very High            | High               | Very High  | Extracts TCP-AO keys for future authentication bypass or session hijacking.                |
| 3.1.2.1 Distributed TCP sequence prediction                           | Very High            | High               | Very High  | Coordinates multiple attackers to predict TCP sequences for BGP session hijacking.         |
| 3.1.2.2 Synchronised BGP session reset attacks                        | High                 | Medium             | High       | Coordinates resets of multiple BGP sessions to cause widespread routing instability.       |
| 3.1.2.3 Cross-platform exploitation campaigns                         | Very High            | High               | Very High  | Targets multiple router platforms and BGP implementations for maximum impact.              |
| 3.2.1 ML-Generated Attack Traffic                                     | Very High            | High               | Very High  | AI generates attack traffic that evades detection and targets BGP specifically.            |
| 3.2.2 Autonomous hijack coordination                                  | Very High            | High               | Very High  | AI coordinates route hijacks across multiple networks autonomously.                        |
| 3.2.3 Adaptive persistence mechanisms                                 | Very High            | High               | Very High  | AI adapts persistence techniques to maintain control despite countermeasures.              |
| 3.2.4 Evolutionary path optimization                                  | Very High            | High               | Very High  | AI optimizes BGP path manipulations for stealth and impact.                                |
| 3.2.5 AI-enhanced TCP-AO cryptographic attacks                        | Very High            | High               | Very High  | AI enhances cryptographic attacks against TCP-AO for authentication bypass.                |
| 3.3.1 Backdoored router firmware/images                               | High                 | High               | Very High  | Compromises firmware or images to introduce backdoors into BGP routers.                    |
| 3.3.2 Malicious BGP optimization tools                                | High                 | Medium             | High       | Distributes tools that contain malware or vulnerabilities to compromise BGP operations.    |
| 3.3.3 Compromised network management software                         | High                 | Medium             | High       | Compromises software used to manage BGP networks for unauthorised access.                  |
| 3.3.4 Pre-installed weak TCP-AO keys in vendor equipment              | Medium               | Low                | High       | Uses weak default keys installed by vendors to compromise BGP authentication.              |