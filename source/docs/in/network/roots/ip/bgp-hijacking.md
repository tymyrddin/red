# BGP hijacking & route leaks

## Attack pattern

BGP hijacking and route leaks exploit the trust-based nature of the Border Gateway Protocol (BGP) to redirect internet traffic maliciously. Attackers announce unauthorized IP prefixes or manipulate routing paths to intercept, monitor, or disrupt traffic, often for espionage, theft, or denial-of-service.

```text
1. BGP Hijacking & Route Leaks [OR]

    1.1 Prefix Hijacking [OR]
    
        1.1.1 Sub-Prefix Hijacking
            1.1.1.1 Announcing a more specific prefix than the legitimate one
            1.1.1.2 Exploiting longest prefix match to attract traffic
            1.1.1.3 Using forged origin AS to inject false routes
            
        1.1.2 Exact-Prefix Hijacking
            1.1.2.1 Announcing someone else's exact prefix without authorization
            1.1.2.2 Using a forged origin AS to hijack traffic
            1.1.2.3 Exploiting lack of route validation
            
        1.1.3 Squatting Attacks
            1.1.3.1 Announcing unallocated or unused IP space
            1.1.3.2 Using IP addresses that are not officially assigned
            1.1.3.3 Creating fake resources in unallocated space
            
    1.2 Path Manipulation [OR]
    
        1.2.1 AS Path Forgery
            1.2.1.1 Shortening AS path to make route more attractive
            1.2.1.2 Using fake AS numbers in path announcements
            1.2.1.3 Manipulating path attributes to influence route selection
            
        1.2.2 Route Leaking
            1.2.2.1 Violating export policies to announce routes to unauthorized peers
            1.2.2.2 Accidental or malicious redistribution of routes
            1.2.2.3 Transit leakage to non-transit peers
            
        1.2.3 Blackholing
            1.2.3.1 Announcing routes to discard traffic (for DoS)
            1.2.3.2 Using blackhole communities maliciously
            1.2.3.3 Redirecting traffic to null interfaces
            
    1.3 Sophisticated Techniques [OR]
    
        1.3.1 Time-Based Attacks
            1.3.1.1 Short-duration hijacks to avoid detection
            1.3.1.2 Pulse hijacking for selective interception
            1.3.1.3 Chronologically coordinated attacks
            
        1.3.2 Targeted Hijacking
            1.3.2.1 Focusing on specific countries or organizations
            1.3.2.2 Hijacking critical infrastructure prefixes
            1.3.2.3 Attacks against financial or government networks
            
        1.3.3 Advanced Persistence
            1.3.3.1 Long-term hijacking for espionage
            1.3.3.2 Low-volume route manipulation
            1.3.3.3 Stealthy path manipulation
            
    1.4 Exploitation Methods [OR]
    
        1.4.1 Rogue AS Attacks
            1.4.1.1 Creating fake autonomous systems
            1.4.1.2 Compromising existing AS infrastructure
            1.4.1.3 Social engineering to obtain AS resources
            
        1.4.2 Compromised Routers
            1.4.2.1 Taking control of BGP routers
            1.4.2.2 Manipulating routing tables directly
            1.4.2.3 Exploiting router vulnerabilities
            
        1.4.3 Social Engineering
            1.4.3.1 Manipulating network operators
            1.4.3.2 Social engineering to change routing policies
            1.4.3.3 Impersonating legitimate network administrators
            
    1.5 Attack Objectives [OR]
    
        1.5.1 Traffic Interception
            1.5.1.1 Man-in-the-middle attacks
            1.5.1.2 Eavesdropping on communications
            1.5.1.3 SSL/TLS interception
            
        1.5.2 Denial of Service
            1.5.2.1 Blackholing traffic
            1.5.2.2 Routing loops
            1.5.2.3 Path inflation
            
        1.5.3 Financial Gain
            1.5.3.1 Cryptocurrency exchange targeting
            1.5.3.2 Ad revenue manipulation
            1.5.3.3 Competitive advantage
            
    1.6 Evasion Techniques [OR]
    
        1.6.1 Detection Avoidance
            1.6.1.1 Short-lived hijacks
            1.6.1.2 Low-volume route leaks
            1.6.1.3 Mimicking legitimate announcements
            
        1.6.2 Attribution Obfuscation
            1.6.2.1 Using compromised infrastructure
            1.6.2.2 Through multiple AS paths
            1.6.2.3 Cross-border routing
            
        1.6.3 Legal Avoidance
            1.6.3.1 Operating in jurisdictions with weak enforcement
            1.6.3.2 Using bulletproof hosting providers
            1.6.3.3 Exploiting legal gray areas
            
    1.7 Coordination Mechanisms [OR]
    
        1.7.1 State-Sponsored Attacks
            1.7.1.1 Nation-state level hijacking
            1.7.1.2 Intelligence gathering operations
            1.7.1.3 Geopolitical targeting
            
        1.7.2 Criminal Syndicates
            1.7.2.1 Organized crime involvement
            1.7.2.2 Ransom-based attacks
            1.7.2.3 Large-scale financial attacks
            
        1.7.3 Insider Threats
            1.7.3.1 Malicious network administrators
            1.7.3.2 Compromised employees
            1.7.3.3 Third-party vendor risks
            
    1.8 Infrastructure Abuse [OR]
    
        1.8.1 Cloud Provider Exploitation
            1.8.1.1 Abusing cloud peering relationships
            1.8.1.2 Manipulating cloud routing policies
            1.8.1.3 Exploiting multi-cloud connectivity
            
        1.8.2 IXP Manipulation
            1.8.2.1 Internet Exchange Point attacks
            1.8.2.2 Route server manipulation
            1.8.2.3 Peering fabric exploitation
            
        1.8.3 Cable System Targeting
            1.8.3.1 Submarine cable route manipulation
            1.8.3.2 Terrestrial fiber path influencing
            1.8.3.3 Cross-continental path manipulation
```

## Why it works

-   Trust-Based Protocol: BGP inherently trusts announcements from peers .
-   Lack of Authentication: No built-in mechanism to verify route legitimacy .
-   Global Scale: Billions of routes exchanged make verification difficult .
-   Complex Policies: Human configuration errors create vulnerabilities .
-   Slow Convergence: BGP's slow convergence helps attacks persist .

## Mitigation

### Resource Public Key Infrastructure (RPKI)

-   Action: Implement cryptographic route origin validation.
-   How:
    -   Create ROAs: Sign your routes with Route Origin Authorizations.
    -   Enable ROV: Configure routers to validate received routes.
    -   Monitor Validity: Regularly check your ROA status.
-   Configuration Example (cisco):

```text
router bgp 65001
 bgp rpki server tcp 10.0.0.1 port 323
 address-family ipv4
  bgp rpki origin-as validation
```

### BGP monitoring and alerting

-   Action: Continuously monitor BGP announcements.
-   How:
    -   BGPmon Services: Use services like BGPMon, Cloudflare Radar, or RIPE Stat.
    -   Custom Monitoring: Implement looking glasses and route collectors.
    -   Real-time Alerts: Set up notifications for unauthorized announcements.
-   Tools: Use open-source tools like BGPStream or commercial services.

### Filtering and policy enforcement

-   Action: Implement strict inbound and outbound filtering.
-   How:
    -   Prefix Filters: Only accept legitimate prefixes from peers.
    -   AS Path Filters: Reject improbable AS paths.
    -   Max-Prefix Limits: Prevent route flooding.
-   Configuration Example:
    ```text
    ip prefix-list LEGITIMATE-PREFIXES seq 10 permit 192.0.2.0/24
    route-map PEER-IN permit 10
     match ip address prefix-list LEGITIMATE-PREFIXES
    ```

### BGP security extensions
-   Action: Implement BGPsec for path validation.
-   How:
    -   Deploy BGPsec: Where supported by vendors and peers.
    -   Phase Implementation: Start with critical peers and expand.
    -   Monitor Performance: Watch for computational overhead.
-   Considerations: BGPsec requires widespread adoption for full effectiveness.

### Peering agreement enforcement:
-   Action: Formalize and enforce peering policies.
-   How:
    -   Signed Agreements: Establish clear peering contracts.
    -   Regular Audits: Review peer configurations periodically.
    -   Violation Response: Have procedures for policy violations.
-   Best Practice: Maintain an up-to-date PeeringDB record.

### Incident response planning
-   Action: Prepare for hijacking incidents.
-   How:
    -   Response Team: Designate a BGP security team.
    -   Communication Plan: Establish contacts with peers and providers.
    -   Recovery Procedures: Document steps to reclaim hijacked prefixes.
-   Template: Maintain incident response checklists.

### MANRS compliance
-   Action: Join the Mutually Agreed Norms for Routing Security.
-   How:
    -   Implement Actions: Fulfill MANRS requirements for your network type.
    -   Get Certified: Undergo MANRS compliance auditing.
    -   Promote Adoption: Encourage peers to join MANRS.
-   Benefits: Improved security and industry recognition.

## Key insights from real-world attacks
-   YouTube Hijack (2008): Pakistan Telecom hijacked YouTube's prefix, causing global outage .
-   Russian Hijacks (2017): Russian ISPs hijacked financial traffic for  minutes .
-   Chinese Attacks (2023): Ongoing hijacking of military and government traffic .

## Future trends and recommendations
-   Automated Validation: AI-based real-time route validation .
-   Blockchain Solutions: Distributed ledger for route attestation .
-   Global Standards: International agreements on routing security .

## Conclusion

BGP hijacking and route leaks threaten internet stability and security. Mitigation requires RPKI deployment, continuous monitoring, strict filtering, and industry cooperation. As attacks grow more sophisticated, proactive measures and global collaboration are essential for maintaining routing security.