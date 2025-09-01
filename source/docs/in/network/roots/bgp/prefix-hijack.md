# IPv4 prefix hijacking

## Attack pattern

IPv4 prefix hijacking occurs when an Autonomous System (AS) maliciously or erroneously announces ownership of IP 
address blocks that belong to another entity. This disrupts internet routing by redirecting traffic through 
unauthorized paths, enabling interception, surveillance, or denial-of-service attacks.

```text
1. IPv4 Prefix Hijacking [OR]

    1.1 Subprefix Hijacking [OR]
    
        1.1.1 Exact Prefix Announcement
            1.1.1.1 Announcing another organisation's exact IPv4 prefix
            1.1.1.2 Using forged origin AS to claim ownership
            1.1.1.3 Exploiting lack of Route Origin Authorization (ROA)
            
        1.1.2 More Specific Prefix Announcement
            1.1.2.1 Announcing a longer prefix (e.g., /24 instead of /22)
            1.1.2.2 Exploiting longest prefix match routing preference
            1.1.2.3 Targeted hijacking of specific subnets
            
    1.2 BGP Path Manipulation [OR]
    
        1.2.1 AS Path Prepending Abuse
            1.2.1.1 Manipulating path length to influence route selection
            1.2.1.2 Creating artificial path preferences
            1.2.1.3 BGP community attribute manipulation
            
        1.2.2 Route Leaking
            1.2.2.1 Violating export policies to transit providers
            1.2.2.2 Accidental or malicious redistribution to peers
            1.2.2.3 Multi-hop route propagation abuse
            
    1.3 Attack Objectives [OR]
    
        1.3.1 Traffic Interception
            1.3.1.1 Man-in-the-middle attacks for surveillance
            1.3.1.2 SSL/TLS certificate manipulation
            1.3.1.3 Data exfiltration through rogue paths
            
        1.3.2 Denial of Service
            1.3.2.1 Blackholing traffic to specific prefixes
            1.3.2.2 Routing loops through inconsistent announcements
            1.3.2.3 Path inflation causing latency and packet loss
            
        1.3.3 Financial Motivation
            1.3.3.1 Cryptocurrency exchange targeting
            1.3.3.2 Ad revenue diversion
            1.3.3.3 Competitive advantage through service disruption
            
    1.4 Evasion Techniques [OR]
    
        1.4.1 Time-Based Attacks
            1.4.1.1 Short-duration hijacks to avoid detection
            1.4.1.2 Pulse hijacking for selective interception
            1.4.1.3 Chronologically coordinated attacks
            
        1.4.2 Geographic Distribution
            1.4.2.1 Multi-region announcement coordination
            1.4.2.2 Exploiting slow global BGP convergence
            1.4.2.3 Targeting specific geographic regions
            
        1.4.3 Attribution Obfuscation
            1.4.3.1 Using compromised AS resources
            1.4.3.2 Route manipulation through multiple hops
            1.4.3.3 False flag operations
            
    1.5 Infrastructure Exploitation [OR]
    
        1.5.1 Rogue ASN Registration
            1.5.1.1 Obtaining AS numbers through fraudulent means
            1.5.1.2 Social engineering against Regional Internet Registries (RIRs)
            1.5.1.3 Exploiting temporary ASN allocations
            
        1.5.2 Compromised Router Access
            1.5.2.1 Unauthorized access to BGP routers
            1.5.2.2 Credential theft for network devices
            1.5.2.3 Vendor backdoor exploitation
            
        1.5.3 IXP Manipulation
            1.5.3.1 Internet Exchange Point route server exploitation
            1.5.3.2 Peering session hijacking
            1.5.3.3 BGP session takeover through MD5 weakness
            
    1.6 Advanced Techniques [OR]
    
        1.6.1 AI-Powered Hijacking
            1.6.1.1 Machine learning for optimal hijack timing
            1.6.1.2 Adaptive attack patterns based on network conditions
            1.6.1.3 Predictive routing manipulation
            
        1.6.2 State-Sponsored Operations
            1.6.2.1 Nation-level prefix hijacking campaigns
            1.6.2.2 Intelligence gathering through traffic interception
            1.6.2.3 Geopolitical targeting of specific nations
            
        1.6.3 Zero-Day Exploitation
            1.6.3.1 Unknown BGP implementation vulnerabilities
            1.6.3.2 Novel route processing flaws
            1.6.3.3 Emerging protocol extension abuse
            
    1.7 Persistence Mechanisms [OR]
    
        1.7.1 Long-Term Hijacking
            1.7.1.1 Sustained prefix announcements for extended periods
            1.7.1.2 Gradual route manipulation to avoid detection
            1.7.1.3 Low-volume traffic interception
            
        1.7.2 Recurrence Patterns
            1.7.2.1 Periodic re-hijacking of same prefixes
            1.7.2.2 Rotating between different target prefixes
            1.7.2.3 Seasonal attack patterns based on traffic volumes
            
    1.8 Collateral Damage [OR]
    
        1.8.1 Internet-Wide Impact
            1.8.1.1 Global routing table pollution
            1.8.1.2 Cascading routing instabilities
            1.8.1.3 Multi-organisational service disruption
            
        1.8.2 Economic Consequences
            1.8.2.1 Financial service disruption
            1.8.2.2 E-commerce revenue loss
            1.8.2.3 Recovery cost burden on victims
```

## Why it works

-   Trust-Based Protocol: BGP inherently trusts announcements from peers without cryptographic verification
-   Limited Validation: Many networks lack Route Origin Authorization (ROA) and RPKI validation
-   Slow Convergence: Global BGP convergence can take minutes, allowing attacks to persist
-   Complexity: Internet-scale routing complexity makes manual verification impractical
-   Economic Factors: Asymmetric incentives where defenders bear costs of protection

## Mitigation

### Resource Public Key Infrastructure (RPKI)
-   Action: Implement cryptographic route origin validation
-   How:
    -   Create Route Origin Authorizations (ROAs) for your prefixes
    -   Configure routers to validate received routes (ROV)
    -   Maintain current ROAs with correct origin AS numbers
-   Configuration example (Cisco):

```text
router bgp 65001
 bgp rpki server tcp 10.0.0.1 port 323
 address-family ipv4
  bgp rpki origin-as validation
```

### BGP monitoring and alerting
-   Action: Continuously monitor BGP announcements for unauthorized changes
-   How:
    -   Subscribe to BGP monitoring services (BGPMon, Cloudflare Radar)
    -   Implement real-time alerting for prefix announcements
    -   Use looking glasses for route verification
-   Tools: BGPStream, RIPE Stat, and commercial monitoring solutions

### Filtering and policy enforcement
-   Action: Implement strict inbound and outbound route filtering
-   How:
    -   Apply prefix filters based on IRR databases
    -   Use AS path filters to reject improbable paths
    -   Implement max-prefix limits to prevent route flooding
-   Configuration Example:

```text
ip prefix-list LEGITIMATE-PREFIXES seq 10 permit 192.0.2.0/24
route-map PEER-IN permit 10
 match ip address prefix-list LEGITIMATE-PREFIXES
```

### BGP Security extensions
-   Action: Deploy BGPsec for path validation where supported
-   How:
    -   Implement BGPsec with cryptographic path validation
    -   Phase deployment starting with critical peers
    -   Monitor performance impact and adjust accordingly
-   Considerations: Requires vendor support and peer participation

### Peering agreement enforcement
-   Action: Formalize and enforce peering policies
-   How:
    -   Establish clear peering contracts with security requirements
    -   Conduct regular configuration audits with peers
    -   Maintain updated PeeringDB records
-   Best Practice: Participate in Mutually Agreed Norms for Routing Security (MANRS)

### Incident response planning
-   Action: Prepare for hijacking incidents with documented procedures
-   How:
    -   Designate a BGP security response team
    -   Establish communication channels with peers and providers
    -   Document prefix reclamation procedures
-   Template: Maintain incident response checklists and contact lists

### MANRS compliance
-   Action: Join and comply with Mutually Agreed Norms for Routing Security
-   How:
    -   Implement MANRS requirements for your network type
    -   Undergo compliance auditing and certification
    -   Promote MANRS adoption among peers
-   Benefits: Improved security posture and industry recognition
