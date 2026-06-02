# Network infrastructure attacks

## Attack pattern

Network infrastructure attacks target the physical and logical components forming the backbone of internet routing systems. These attacks focus on internet exchange points, route servers, management interfaces, and supporting systems that enable BGP operations. By compromising critical infrastructure elements, adversaries can achieve widespread impact on routing integrity, traffic flow, and network stability across multiple autonomous systems.

```text
1. Network infrastructure attacks [OR]

    1.1 Internet exchange point and route server targeting [OR]
    
        1.1.1 Compromised internet exchange point route server software
            1.1.1.1 Exploitation of software vulnerabilities in route server implementations
            1.1.1.2 Configuration manipulation via administrative access
            1.1.1.3 Malicious route injection through compromised server instances
            1.1.1.4 Denial of service against route server functionality
            
        1.1.2 BGP peering link interception
            1.1.2.1 Physical link compromise at exchange points
            1.1.2.2 Optical signal tapping on peering connections
            1.1.2.3 Switching infrastructure compromise for traffic diversion
            1.1.2.4 VLAN hopping and layer 2 attacks against peering networks
            
        1.1.3 Route reflector compromise
            1.1.3.1 Exploitation of route reflector software vulnerabilities
            1.1.3.2 Reflection attack amplification through compromised reflectors
            1.1.3.3 Malicious route propagation via reflector infrastructure
            1.1.3.4 Resource exhaustion attacks against reflector systems
            
    1.2 Management interface exploitation [OR]
    
        1.2.1 Exposed BGP monitoring systems
            1.2.1.1 Unauthorised access to BGP monitoring platforms
            1.2.1.2 Information leakage from route collection systems
            1.2.1.3 Manipulation of monitoring data for false analysis
            1.2.1.4 Denial of service against network visibility systems
            
        1.2.2 Compromised SSH keys for router access
            1.2.2.1 Theft of private keys from management systems
            1.2.2.2 Exploitation of weak key generation algorithms
            1.2.2.3 Compromise of key management systems
            1.2.2.4 Session hijacking via key compromise
            
        1.2.3 Default credentials on administrative interfaces
            1.2.3.1 Exploitation of factory default passwords
            1.2.3.2 Weak authentication protocol support
            1.2.3.3 Credential brute force attacks
            1.2.3.4 Authentication bypass via misconfiguration
            
        1.2.4 TCP authentication option key material theft via configuration leaks
            1.2.4.1 Interception of configuration backups
            1.2.4.2 Compromise of source code repositories containing keys
            1.2.4.3 Debug information leakage with key material
            1.2.4.4 Memory dump analysis for key extraction
            
    1.3 Supporting system compromise [OR]
    
        1.3.1 Network Time Protocol exploitation
            1.3.1.1 Time synchronisation attacks affecting BGP operations
            1.3.1.2 NTP server compromise for timeline manipulation
            1.3.1.3 Amplification attacks using NTP services
            1.3.1.4 Exploitation of protocol vulnerabilities in time synchronisation
            
        1.3.2 Domain Name System infrastructure targeting
            1.3.2.1 DNS resolver compromise for BGP peer resolution
            1.3.2.2 Cache poisoning attacks affecting route announcements
            1.3.2.3 Denial of service against DNS infrastructure
            1.3.2.4 Exploitation of DNSSEC implementation vulnerabilities
            
        1.3.3 Certificate authority and PKI targeting
            1.3.3.1 CA compromise for fraudulent certificate issuance
            1.3.3.2 Certificate revocation list manipulation
            1.3.3.3 Trust store poisoning attacks
            1.3.3.4 Theft of cryptographic key material from PKI systems
            
    1.4 Physical infrastructure attacks [OR]
    
        1.4.1 Data centre physical security compromise
            1.4.1.1 Unauthorised physical access to networking equipment
            1.4.1.2 Hardware tampering and implant installation
            1.4.1.3 Power supply manipulation attacks
            1.4.1.4 Environmental control system compromise
            
        1.4.2 Optical network targeting
            1.4.2.1 Fibre optic cable tapping and interception
            1.4.2.2 Optical signal amplification attacks
            1.4.2.3 Wavelength division multiplexing manipulation
            1.4.2.4 Optical switching infrastructure compromise
            
        1.4.3 Supply chain compromise
            1.4.3.1 Hardware implant insertion during manufacturing
            1.4.3.2 Firmware modification during distribution
            1.4.3.3 Malicious software pre-installation
            1.4.3.4 Documentation and specification manipulation
```

## Why it works

* Centralised infrastructure: Internet exchange points and route servers represent concentrated points of failure
* Management complexity: Large networks have numerous management interfaces and access points
* Legacy systems: Critical infrastructure often runs on outdated systems with known vulnerabilities
* Physical access requirements: Physical security measures may be inadequate or inconsistently applied
* Supply chain trust: Global supply chains introduce multiple points of potential compromise
* Operational transparency: Monitoring and management systems require exposure that can be exploited
* Configuration complexity: Complex network configurations often contain security oversights

## Counter moves

Network infrastructure attacks is the case here. Stateful filtering and anomaly detection on the handshake are the answer. The defender's view is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
