# Attack tree (BGP and MP-BGP)

```text
1. Compromise BGP/MP-BGP Routing [OR]

    1.1 Initial Access & Infrastructure Compromise [OR]
    
        1.1.1 Social Engineering & Phishing [OR]
        
            1.1.1.1 Target network engineers with BGP config malware
            1.1.1.2 Impersonate RIR staff for ROA manipulation
            1.1.1.3 Fake vendor support requests for credential theft
            
        1.1.2 Exploiting Management Interfaces [OR]
        
            1.1.2.1 Exposed BGP monitoring systems (Grafana/Kibana)
            1.1.2.2 Compromised SSH keys for router access
            1.1.2.3 Default credentials on router admin interfaces
            
        1.1.3 Supply Chain Attacks [OR]
        
            1.1.3.1 Backdoored router firmware/images
            1.1.3.2 Compromised IXP route server software
            1.1.3.3 Malicious BGP optimization tools
            
    1.2 BGP Protocol Attacks [OR]
    
        1.2.1 Session Manipulation [OR]
        
            1.2.1.1 TCP RST injection [AND]
                |-> No TCP-AO/MD5 authentication
                |-> On-path position
            1.2.1.2 Keepalive timer exhaustion attacks
            1.2.1.3 BGP session spoofing with forged source IPs
            
        1.2.2 Update Flooding [OR]
        
            1.2.2.1 Route flap storms (announce/withdraw)
            1.2.2.2 Massive de-aggregation attacks
            1.2.2.3 AS-path prepending storms
            
    1.3 Persistence & Evasion [OR]
    
        1.3.1 Route Poisoning [OR]
        
            1.3.1.1 Selective route announcements during low traffic
            1.3.1.2 Time-based hijacking (short-lived attacks)
            1.3.1.3 Geographic-specific route manipulation
            
        1.3.2 Detection Evasion [OR]
        
            1.3.2.1 Mimicking legitimate AS-path patterns
            1.3.2.2 Abuse of RPKI 'unknown' state
            1.3.2.3 Leveraging peer conflicts for ambiguity
            
2. Protocol-Specific Attacks [OR]

    2.1 Classic BGP (IPv4) Attacks [OR]
    
        2.1.1 IPv4 Prefix Hijacking [OR]
        
            2.1.1.1 Sub-prefix hijacking (more specific routes)
            2.1.1.2 Exact-prefix hijacking with forged origin
            2.1.1.3 Squatting unallocated IPv4 space
            
        2.1.2 IPv4 Path Manipulation [OR]
        
            2.1.2.1 AS-path prepending for traffic engineering
            2.1.2.2 Ghost AS insertion for origin hiding
            2.1.2.3 Community attribute abuse
            
        2.1.3 IPv4 Infrastructure Attacks [OR]
        
            2.1.3.1 Route reflector compromise
            2.1.3.2 BGP router memory exhaustion
            2.1.3.3 Max-prefix limit exploitation
            
    2.2 MP-BGP Specific Attacks [OR]
    
        2.2.1 Multiprotocol NLRl Attacks [OR]
        
            2.2.1.1 VPNv4 route injection [AND]
                |-> Route Distinguisher guessing/bruteforcing
                |-> VPN label spoofing
            2.2.1.2 EVPN MAC/IP advertisement spoofing
            2.2.1.3 IPv6 next-hop poisoning
            
        2.2.2 Address Family Exploitation [OR]
        
            2.2.2.1 Rare AFI/SAFI flooding (e.g., multicast)
            2.2.2.2 Cross-AFI contamination attacks
            2.2.2.3 MP_REACH_NLRI attribute manipulation
            
        2.2.3 MP-BGP Session Attacks [OR]
        
            2.2.3.1 Capability negotiation exploitation
            2.2.3.2 Multi-session AFI exhaustion
            2.2.3.3 Extended community forgery
            
    2.3 BGP-Agnostic Attacks [OR]
    
        2.3.1 RPKI Infrastructure Attacks [OR]
        
            2.3.1.1 RTR (RPKI-to-Router) protocol exploitation
            2.3.1.2 ROA expiration/time manipulation
            2.3.1.3 RIR portal compromise for ROA creation
            
        2.3.2 DDoS Amplification [OR]
        
            2.3.2.1 BGP update reflection/amplification
            2.3.2.2 Route server DDoS via query flooding
            2.3.2.3 Looking glass abuse for amplification
            
        2.3.3 Cryptographic Attacks [OR]
        
            2.3.3.1 BGPsec key compromise
            2.3.3.2 TCP-AO hash collision attacks
            2.3.3.3 RPKI certificate chain exploitation
            
3. Cross-Protocol & Composite Attacks [OR]

    3.1 BGP + DNS Attacks [OR]
    
        3.1.1 Recursive resolver hijacking [AND]
            |-> BGP prefix hijack
            |-> DNS poisoning/compromise
        3.1.2 Authoritative NS redirect [AND]
            |-> Nameserver prefix hijack
            |-> DNSSEC compromise
            
    3.2 BGP + CDN/Cloud Attacks [OR]
    
        3.2.1 Anycast prefix hijacking [AND]
            |-> CDN edge node hijack
            |-> SSL certificate forgery
        3.2.2 Cloud region isolation [AND]
            |-> Regional prefix hijack
            |-> Tenant isolation bypass
            
    3.3 AI-Powered Attacks [OR]
    
        3.3.1 ML-Generated Path Forgery
        3.3.2 Autonomous hijack coordination
        3.3.3 Adaptive persistence mechanisms
```