# BGP hijacking & route leaks

## Attack pattern

BGP hijacking and route leaks exploit the trust-based nature of the border gateway protocol (BGP) to redirect internet traffic maliciously. Attackers announce unauthorised ip prefixes or manipulate routing paths to intercept, monitor, or disrupt traffic, often for espionage, theft, or denial-of-service.

```text
1. BGP hijacking & route leaks [OR]

    1.1 Prefix hijacking [OR]
    
        1.1.1 Sub-prefix hijacking
            1.1.1.1 Announcing a more specific prefix than the legitimate one
            1.1.1.2 Exploiting longest prefix match to attract traffic
            1.1.1.3 Using forged origin AS to inject false routes
            
        1.1.2 Exact-prefix hijacking
            1.1.2.1 Announcing someone else's exact prefix without authorisation
            1.1.2.2 Using a forged origin AS to hijack traffic
            1.1.2.3 Exploiting lack of route validation
            
        1.1.3 Squatting attacks
            1.1.3.1 Announcing unallocated or unused ip space
            1.1.3.2 Using ip addresses that are not officially assigned
            1.1.3.3 Creating fake resources in unallocated space
            
    1.2 Path manipulation [OR]
    
        1.2.1 AS path forgery
            1.2.1.1 Shortening AS path to make route more attractive
            1.2.1.2 Using fake AS numbers in path announcements
            1.2.1.3 Manipulating path attributes to influence route selection
            
        1.2.2 Route leaking
            1.2.2.1 Violating export policies to announce routes to unauthorised peers
            1.2.2.2 Accidental or malicious redistribution of routes
            1.2.2.3 Transit leakage to non-transit peers
            
        1.2.3 Blackholing
            1.2.3.1 Announcing routes to discard traffic (for DoS)
            1.2.3.2 Using blackhole communities maliciously
            1.2.3.3 Redirecting traffic to null interfaces
            
    1.3 Sophisticated techniques [OR]
    
        1.3.1 Time-based attacks
            1.3.1.1 Short-duration hijacks to avoid detection
            1.3.1.2 Pulse hijacking for selective interception
            1.3.1.3 Chronologically coordinated attacks
            
        1.3.2 Targeted hijacking
            1.3.2.1 Focusing on specific countries or organisations
            1.3.2.2 Hijacking critical infrastructure prefixes
            1.3.2.3 Attacks against financial or government networks
            
        1.3.3 Advanced persistence
            1.3.3.1 Long-term hijacking for espionage
            1.3.3.2 Low-volume route manipulation
            1.3.3.3 Stealthy path manipulation
            
    1.4 Exploitation methods [OR]
    
        1.4.1 Rogue AS attacks
            1.4.1.1 Creating fake autonomous systems
            1.4.1.2 Compromising existing AS infrastructure
            1.4.1.3 Social engineering to obtain AS resources
            
        1.4.2 Compromised routers
            1.4.2.1 Taking control of BGP routers
            1.4.2.2 Manipulating routing tables directly
            1.4.2.3 Exploiting router vulnerabilities
            
        1.4.3 Social engineering
            1.4.3.1 Manipulating network operators
            1.4.3.2 Social engineering to change routing policies
            1.4.3.3 Impersonating legitimate network administrators
            
    1.5 Attack objectives [OR]
    
        1.5.1 Traffic interception
            1.5.1.1 Man-in-the-middle attacks
            1.5.1.2 Eavesdropping on communications
            1.5.1.3 SSL/TLS interception
            
        1.5.2 Denial of service
            1.5.2.1 Blackholing traffic
            1.5.2.2 Routing loops
            1.5.2.3 Path inflation
            
        1.5.3 Financial gain
            1.5.3.1 Cryptocurrency exchange targeting
            1.5.3.2 Ad revenue manipulation
            1.5.3.3 Competitive advantage
            
    1.6 Evasion techniques [OR]
    
        1.6.1 Detection avoidance
            1.6.1.1 Short-lived hijacks
            1.6.1.2 Low-volume route leaks
            1.6.1.3 Mimicking legitimate announcements
            
        1.6.2 Attribution obfuscation
            1.6.2.1 Using compromised infrastructure
            1.6.2.2 Through multiple AS paths
            1.6.2.3 Cross-border routing
            
        1.6.3 Legal avoidance
            1.6.3.1 Operating in jurisdictions with weak enforcement
            1.6.3.2 Using bulletproof hosting providers
            1.6.3.3 Exploiting legal grey areas
            
    1.7 Coordination mechanisms [OR]
    
        1.7.1 State-sponsored attacks
            1.7.1.1 Nation-state level hijacking
            1.7.1.2 Intelligence gathering operations
            1.7.1.3 Geopolitical targeting
            
        1.7.2 Criminal syndicates
            1.7.2.1 Organised crime involvement
            1.7.2.2 Ransom-based attacks
            1.7.2.3 Large-scale financial attacks
            
        1.7.3 Insider threats
            1.7.3.1 Malicious network administrators
            1.7.3.2 Compromised employees
            1.7.3.3 Third-party vendor risks
            
    1.8 Infrastructure abuse [OR]
    
        1.8.1 Cloud provider exploitation
            1.8.1.1 Abusing cloud peering relationships
            1.8.1.2 Manipulating cloud routing policies
            1.8.1.3 Exploiting multi-cloud connectivity
            
        1.8.2 IXP manipulation
            1.8.2.1 Internet exchange point attacks
            1.8.2.2 Route server manipulation
            1.8.2.3 Peering fabric exploitation
            
        1.8.3 Cable system targeting
            1.8.3.1 Submarine cable route manipulation
            1.8.3.2 Terrestrial fibre path influencing
            1.8.3.3 Cross-continental path manipulation
```

## Why it works

-   Trust-based protocol: BGP inherently trusts announcements from peers
-   Lack of authentication: No built-in mechanism to verify route legitimacy
-   Global scale: Billions of routes exchanged make verification difficult
-   Complex policies: Human configuration errors create vulnerabilities
-   Slow convergence: BGP's slow convergence helps attacks persist

## Mitigation

### Resource public key infrastructure (RPKI)

-   Action: Implement cryptographic route origin validation
-   How:
    -   Create roas: Sign your routes with route origin authorisations
    -   Enable rov: Configure routers to validate received routes
    -   Monitor validity: Regularly check your roa status

### BGP monitoring and alerting

-   Action: Continuously monitor BGP announcements
-   How:
    -   BGPmon services: Use services like BGPmon, cloudflare radar, or ripe stat
    -   Custom monitoring: Implement looking glasses and route collectors
    -   Real-time alerts: Set up notifications for unauthorised announcements

### Filtering and policy enforcement

-   Action: Implement strict inbound and outbound filtering
-   How:
    -   Prefix filters: Only accept legitimate prefixes from peers
    -   AS path filters: Reject improbable AS paths
    -   Max-prefix limits: Prevent route flooding

### BGP security extensions

-   Action: Implement BGPsec for path validation
-   How:
    -   Deploy BGPsec: Where supported by vendors and peers
    -   Phase implementation: Start with critical peers and expand
    -   Monitor performance: Watch for computational overhead

### Peering agreement enforcement

-   Action: Formalise and enforce peering policies
-   How:
    -   Signed agreements: Establish clear peering contracts
    -   Regular audits: Review peer configurations periodically
    -   Violation response: Have procedures for policy violations

### Incident response planning

-   Action: Prepare for hijacking incidents
-   How:
    -   Response team: Designate a BGP security team
    -   Communication plan: Establish contacts with peers and providers
    -   Recovery procedures: Document steps to reclaim hijacked prefixes

### MANRS compliance

-   Action: Join the mutually agreed norms for routing security
-   How:
    -   Implement actions: Fulfill manrs requirements for your network type
    -   Get certified: Undergo manrs compliance auditing
    -   Promote adoption: Encourage peers to join manrs

## Key insights from real-world attacks

-   Youtube hijack (2008): Pakistan telecom hijacked youtube's prefix, causing global outage
-   Russian hijacks (2017): Russian isps hijacked financial traffic for minutes
-   Chinese attacks (2023): Ongoing hijacking of military and government traffic

## Future trends and recommendations

-   Automated validation: AI-based real-time route validation
-   Blockchain solutions: Distributed ledger for route attestation
-   Global standards: International agreements on routing security

## Conclusion

BGP hijacking and route leaks threaten internet stability and security. Mitigation requires RPKI deployment, continuous monitoring, strict filtering, and industry cooperation. As attacks grow more sophisticated, proactive measures and global collaboration are essential for maintaining routing security.
