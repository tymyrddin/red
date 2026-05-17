# IPv4 infrastructure attacks

## Attack pattern

Internet Protocol version 4 (IPv4) infrastructure attacks target the core network components and services that facilitate IPv4 communication. These attacks exploit vulnerabilities in routers, servers, and supporting systems to disrupt services, intercept traffic, or gain unauthorised access to network resources.

```text
1. IPv4 infrastructure attacks [OR]

    1.1 Router targeting [OR]
    
        1.1.1 Control plane exploitation
            1.1.1.1 BGP session hijacking
            1.1.1.2 OSPF/IS-IS adjacency manipulation
            1.1.1.3 Routing table poisoning
            
        1.1.2 Management plane attacks
            1.1.2.1 Default credential exploitation
            1.1.2.2 SNMP community string attacks
            1.1.2.3 Remote management service exploitation
            
        1.1.3 Data plane targeting
            1.1.3.1 ACL bypass techniques
            1.1.3.2 Forwarding table corruption
            1.1.3.3 Buffer exhaustion attacks
            
    1.2 Server infrastructure targeting [OR]
    
        1.2.1 DNS server exploitation
            1.2.1.1 Cache poisoning attacks
            1.2.1.2 Zone transfer exploitation
            1.2.1.3 Recursive query abuse
            
        1.2.2 DHCP server attacks
            1.2.2.1 Rogue server implantation
            1.2.2.2 Lease exhaustion attacks
            1.2.2.3 Option manipulation
            
        1.2.3 NTP server targeting
            1.2.3.1 Time synchron attacks
            1.2.3.2 Monlist command exploitation
            1.2.3.3 Stratum manipulation
            
    1.3 Network service disruption [OR]
    
        1.3.1 ARP infrastructure attacks
            1.3.1.1 Gratuitous ARP flooding
            1.3.1.2 Proxy ARP exploitation
            1.3.1.3 ARP table overflow
            
        1.3.2 ICMP-based attacks
            1.3.2.1 Redirect message abuse
            1.3.2.2 Address mask exploitation
            1.3.2.3 Router advertisement manipulation
            
        1.3.3 TCP service targeting
            1.3.3.1 SYN flood amplification
            1.3.3.2 Connection table exhaustion
            1.3.3.3 Sequence number prediction
            
    1.4 Security device exploitation [OR]
    
        1.4.1 Firewall bypass techniques
            1.4.1.1 Fragmentation attacks
            1.4.1.2 Protocol ambiguity exploitation
            1.4.1.3 State table exhaustion
            
        1.4.2 Intrusion prevention system evasion
            1.4.2.1 Traffic normalisation bypass
            1.4.2.2 Signature evasion techniques
            1.4.2.3 Performance exhaustion attacks
            
        1.4.3 VPN concentrator targeting
            1.4.3.1 IKE negotiation exploitation
            1.4.3.2 Tunnel establishment attacks
            1.4.3.3 Pre-shared key compromise
            
    1.5 Management infrastructure attacks [OR]
    
        1.5.1 Network management system targeting
            1.5.1.1 SNMP exploitation
            1.5.1.2 NetFlow data manipulation
            1.5.1.3 Syslog message injection
            
        1.5.2 Monitoring system disruption
            1.5.2.1 Alert flooding
            1.5.2.2 Performance data manipulation
            1.5.2.3 Dashboard compromise
            
        1.5.3 Configuration management attacks
            1.5.3.1 Configuration file manipulation
            1.5.3.2 Change management bypass
            1.5.3.3 Backup system compromise
            
    1.6 Physical infrastructure targeting [OR]
    
        1.6.1 Cable infrastructure attacks
            1.6.1.1 Tap installation
            1.6.1.2 Cable damage or destruction
            1.6.1.3 Signal interception
            
        1.6.2 Device physical access
            1.6.2.1 Console port exploitation
            1.6.2.2 Hardware modification
            1.6.2.3 Firmware manipulation
            
        1.6.3 Power system attacks
            1.6.3.1 UPS system targeting
            1.6.3.2 Power overload attacks
            1.6.3.3 Cooling system disruption
            
    1.7 Protocol implementation attacks [OR]
    
        1.7.1 Stack vulnerability exploitation
            1.7.1.1 Buffer overflow attacks
            1.7.1.2 Integer handling vulnerabilities
            1.7.1.3 Memory corruption exploits
            
        1.7.2 Parser targeting
            1.7.2.1 Packet parsing vulnerabilities
            1.7.2.2 Header manipulation attacks
            1.7.2.3 Option processing exploitation
            
        1.7.3 Timer and state attacks
            1.7.3.1 Timer exhaustion attacks
            1.7.3.2 State machine manipulation
            1.7.3.3 Resource cleanup exploitation
            
    1.8 Support system attacks [OR]
    
        1.8.1 Time synchronisation attacks
            1.8.1.1 NTP server compromise
            1.8.1.2 Time skew exploitation
            1.8.1.3 Certificate validation bypass
            
        1.8.2 Logging system targeting
            1.8.2.1 Log message injection
            1.8.2.2 Log file manipulation
            1.8.2.3 Log storage exhaustion
            
        1.8.3 Authentication system attacks
            1.8.3.1 RADIUS/TACACS+ exploitation
            1.8.3.2 Certificate authority targeting
            1.8.3.3 Credential storage compromise
```

## Why it works

-   Protocol age: IPv4's longevity means many systems run outdated implementations with known vulnerabilities
-   Complexity: Modern IPv4 infrastructures involve numerous interconnected systems with complex configurations
-   Default configurations: Many devices ship with insecure default settings that are never properly secured
-   Management access exposure: Network management interfaces are often exposed to broader networks than necessary
-   Legacy systems: Critical infrastructure frequently incorporates outdated systems that cannot be patched or replaced
-   Interdependency attacks: Compromising one system often provides access to connected systems and services
