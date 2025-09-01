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

## Risk table

| Attack Path                                               | Technical Complexity | Resources Required | Risk Level | Notes                                                            |
|-----------------------------------------------------------|----------------------|--------------------|------------|------------------------------------------------------------------|
| 1.1.1.1 Target network engineers with BGP config malware  | High                 | Medium             | High       | Needs social engineering and malware development.                |
| 1.1.1.2 Impersonate RIR staff for ROA manipulation        | High                 | Medium             | High       | Phishing or spoofing regulatory staff; targeted.                 |
| 1.1.1.3 Fake vendor support requests for credential theft | Medium               | Low                | Medium     | Social engineering; depends on human error.                      |
| 1.1.2.1 Exposed BGP monitoring systems (Grafana/Kibana)   | Medium               | Low                | Medium     | Requires scanning and access; opportunistic.                     |
| 1.1.2.2 Compromised SSH keys for router access            | High                 | Medium             | High       | Accessing routers; advanced network knowledge needed.            |
| 1.1.2.3 Default credentials on router admin interfaces    | Low                  | Low                | Medium     | Simple but high impact if not patched.                           |
| 1.1.3.1 Backdoored router firmware/images                 | Very High            | High               | Very High  | Supply chain compromise; difficult but extremely impactful.      |
| 1.1.3.2 Compromised IXP route server software             | Very High            | High               | Very High  | Infrastructure-level attack; sophisticated.                      |
| 1.1.3.3 Malicious BGP optimization tools                  | High                 | Medium             | High       | Requires targeted deployment to operators.                       |
| 1.2.1.1 TCP RST injection                                 | High                 | High               | High       | Requires on-path access and no authentication.                   |
| 1.2.1.2 Keepalive timer exhaustion attacks                | Medium               | Medium             | Medium     | Automated attack; moderately difficult.                          |
| 1.2.1.3 BGP session spoofing with forged source IPs       | High                 | Medium             | High       | Needs control over traffic path; complex.                        |
| 1.2.2.1 Route flap storms                                 | High                 | Medium             | High       | Large-scale announcement/withdraw attacks.                       |
| 1.2.2.2 Massive de-aggregation attacks                    | High                 | Medium             | High       | Disrupts routing tables; technical skill required.               |
| 1.2.2.3 AS-path prepending storms                         | Medium               | Medium             | Medium     | Moderately disruptive; requires coordination.                    |
| 1.3.1.1 Selective route announcements during low traffic  | Medium               | Low                | Medium     | Timing-sensitive manipulation; moderate skill.                   |
| 1.3.1.2 Time-based hijacking (short-lived attacks)        | High                 | Medium             | High       | Requires precise timing; stealthy.                               |
| 1.3.1.3 Geographic-specific route manipulation            | High                 | Medium             | High       | Knowledge of regional routing; targeted impact.                  |
| 1.3.2.1 Mimicking legitimate AS-path patterns             | High                 | Medium             | High       | Evades detection; requires routing expertise.                    |
| 1.3.2.2 Abuse of RPKI 'unknown' state                     | Medium               | Medium             | Medium     | Exploits protocol ambiguity; moderate skill.                     |
| 1.3.2.3 Leveraging peer conflicts for ambiguity           | Medium               | Medium             | Medium     | Relies on network relationships; moderate effort.                |
| 2.1.1.1 Sub-prefix hijacking                              | High                 | Medium             | High       | Diverts traffic for targeted prefixes; technical skill required. |
| 2.1.1.2 Exact-prefix hijacking with forged origin         | High                 | Medium             | High       | Highly disruptive; requires forged announcements.                |
| 2.1.1.3 Squatting unallocated IPv4 space                  | Medium               | Medium             | Medium     | Opportunistic; requires routing control.                         |
| 2.1.2.1 AS-path prepending for traffic engineering        | Medium               | Low                | Medium     | Low-cost traffic manipulation; detectable.                       |
| 2.1.2.2 Ghost AS insertion for origin hiding              | High                 | Medium             | High       | Advanced; hides origin in AS-path.                               |
| 2.1.2.3 Community attribute abuse                         | Medium               | Low                | Medium     | Manipulates routing preferences; moderate impact.                |
| 2.1.3.1 Route reflector compromise                        | Very High            | High               | Very High  | Infrastructure-level; highly technical.                          |
| 2.1.3.2 BGP router memory exhaustion                      | High                 | Medium             | High       | Denial-of-service via resource exhaustion.                       |
| 2.1.3.3 Max-prefix limit exploitation                     | Medium               | Medium             | Medium     | Moderate disruption; needs misconfiguration.                     |
| 2.2.1.1 VPNv4 route injection                             | Very High            | High               | Very High  | Requires RD guessing and label spoofing; advanced.               |
| 2.2.1.2 EVPN MAC/IP advertisement spoofing                | High                 | Medium             | High       | Targeted virtual network attack; technical.                      |
| 2.2.1.3 IPv6 next-hop poisoning                           | High                 | Medium             | High       | Advanced manipulation; moderate resources.                       |
| 2.2.2.1 Rare AFI/SAFI flooding                            | High                 | Medium             | High       | Exploits uncommon address families; sophisticated.               |
| 2.2.2.2 Cross-AFI contamination attacks                   | High                 | Medium             | High       | Complex manipulation; needs network knowledge.                   |
| 2.2.2.3 MP\_REACH\_NLRI attribute manipulation            | High                 | Medium             | High       | Technical; affects multi-protocol routing.                       |
| 2.2.3.1 Capability negotiation exploitation               | High                 | Medium             | High       | Requires session-level manipulation.                             |
| 2.2.3.2 Multi-session AFI exhaustion                      | High                 | Medium             | High       | Resource-intensive; complex.                                     |
| 2.2.3.3 Extended community forgery                        | High                 | Medium             | High       | Advanced routing attack; targeted.                               |
| 2.3.1.1 RTR protocol exploitation                         | High                 | Medium             | High       | Exploits RPKI infrastructure; technical.                         |
| 2.3.1.2 ROA expiration/time manipulation                  | Medium               | Medium             | Medium     | Relies on timing; moderate impact.                               |
| 2.3.1.3 RIR portal compromise for ROA creation            | High                 | High               | High       | Needs access to RIR systems; very impactful.                     |
| 2.3.2.1 BGP update reflection/amplification               | High                 | Medium             | High       | Can be used for DDoS amplification; sophisticated.               |
| 2.3.2.2 Route server DDoS via query flooding              | Medium               | Medium             | Medium     | Moderate-scale amplification; network access needed.             |
| 2.3.2.3 Looking glass abuse for amplification             | Medium               | Low                | Medium     | Opportunistic; low-resource attack.                              |
| 2.3.3.1 BGPsec key compromise                             | Very High            | High               | Very High  | High-impact cryptographic attack; highly technical.              |
| 2.3.3.2 TCP-AO hash collision attacks                     | Very High            | High               | Very High  | Advanced crypto attack; rare but severe.                         |
| 2.3.3.3 RPKI certificate chain exploitation               | Very High            | High               | Very High  | Cryptographic exploitation; complex and high-risk.               |
| 3.1.1 Recursive resolver hijacking                        | Very High            | High               | Very High  | Requires BGP hijack + DNS compromise; complex.                   |
| 3.1.2 Authoritative NS redirect                           | Very High            | High               | Very High  | Combination of routing and DNSSEC compromise; highly technical.  |
| 3.2.1 Anycast prefix hijacking                            | Very High            | High               | Very High  | CDN edge and certificate forgery; very resource intensive.       |
| 3.2.2 Cloud region isolation                              | Very High            | High               | Very High  | Regional routing + tenant isolation; extremely difficult.        |
| 3.3.1 ML-generated path forgery                           | Very High            | High               | Very High  | AI-assisted routing attacks; cutting-edge.                       |
| 3.3.2 Autonomous hijack coordination                      | Very High            | High               | Very High  | Coordinated AI attacks; highly sophisticated.                    |
| 3.3.3 Adaptive persistence mechanisms                     | Very High            | High               | Very High  | Self-adjusting attacks; very hard to detect and mitigate.        |


