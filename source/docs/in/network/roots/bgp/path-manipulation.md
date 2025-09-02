# IPv4 path manipulation

## Attack Pattern

IPv4 path manipulation involves altering the Border Gateway Protocol (BGP) path attributes to maliciously influence routing decisions across the internet. By exploiting BGP's trust-based nature, attackers can redirect traffic through unauthorised paths, create routing loops, or implement denial-of-service conditions.

```text
1. IPv4 Path Manipulation [OR]

    1.1 AS Path Attribute Manipulation [OR]
    
        1.1.1 AS Path Prepending
            1.1.1.1 Adding fake AS segments to make paths appear longer
            1.1.1.2 Strategic prepending to influence route selection
            1.1.1.3 Multi-hop prepending for extended manipulation
            
        1.1.2 AS Path Shortening
            1.1.2.1 Forging shorter AS paths to attract traffic
            1.1.2.2 Removing legitimate AS segments from paths
            1.1.2.3 Creating fake optimal paths through path truncation
            
        1.1.3 AS Path Poisoning
            1.1.3.1 Inserting non-existent AS numbers
            1.1.3.2 Using reserved or private AS numbers in paths
            1.1.3.3 Creating invalid AS path sequences
            
    1.2 BGP Community Attribute Abuse [OR]
    
        1.2.1 Community-Based Traffic Engineering
            1.2.1.1 Manipulating traffic flow using community attributes
            1.2.1.2 Exploiting provider-specific community meanings
            1.2.1.3 Unauthorized use of no-export and other communities
            
        1.2.2 Blackhole Community Manipulation
            1.2.2.1 Illegitimately tagging routes with blackhole communities
            1.2.2.2 Creating denial-of-service through route blackholing
            1.2.2.3 Exploiting provider blackhole infrastructure
            
        1.2.3 QoS Community Exploitation
            1.2.3.1 Manipulating quality of service through communities
            1.2.3.2 Priority manipulation for traffic classes
            1.2.3.3 Bandwidth allocation abuse
            
    1.3 MED (Multi-Exit Discriminator) Manipulation [OR]
    
        1.3.1 MED Attribute Forgery
            1.3.1.1 Setting artificial MED values to influence path selection
            1.3.1.2 Exploiting MED comparison rules between different ASs
            1.3.1.3 Creating preferential exit point selection
            
        1.3.2 MED-Based Traffic Steering
            1.3.2.1 Redirecting traffic to specific interconnection points
            1.3.2.2 Manipulating inbound traffic engineering
            1.3.2.3 Exploiting multi-homed network configurations
            
    1.4 Next-Hop Manipulation [OR]
    
        1.4.1 Next-Hop Attribute Spoofing
            1.4.1.1 Forging next-hop addresses to redirect traffic
            1.4.1.2 Using unreachable next-hops for blackholing
            1.4.1.3 Creating routing loops through next-hop manipulation
            
        1.4.2 Third-Party Next-Hop Abuse
            1.4.2.1 Specifying unauthorized third-party next-hops
            1.4.2.2 Exploiting next-hop-self configurations
            1.4.2.3 Using next-hop to bypass security policies
            
    1.5 Origin Attribute Manipulation [OR]
    
        1.5.1 Origin Type Forgery
            1.5.1.1 Changing origin attribute from IGP to EGP or INCOMPLETE
            1.5.1.2 Exploiting origin type preferences in path selection
            1.5.1.3 Manipulating route authenticity through origin changes
            
        1.5.2 False Origin AS Claims
            1.5.2.1 Claiming origin from unauthorized AS numbers
            1.5.2.2 Using hijacked or revoked AS numbers
            1.5.2.3 Origin spoofing for false attribution
            
    1.6 Weight and Local Preference Abuse [OR]
    
        1.6.1 Local Preference Manipulation
            1.6.1.1 Illegitimately setting high local preference values
            1.6.1.2 Influencing outbound traffic flow through local pref
            1.6.1.3 Creating routing inconsistencies within AS
            
        1.6.2 Weight Attribute Exploitation
            1.6.2.1 Manipulating Cisco-specific weight attribute
            1.6.2.2 Creating preferred paths through weight manipulation
            1.6.2.3 Bypassing normal BGP decision process
            
    1.7 Route Reflection Manipulation [OR]
    
        1.7.1 Rogue Route Reflector
            1.7.1.1 Compromising route reflector infrastructure
            1.7.1.2 Injecting malicious routes through reflectors
            1.7.1.3 Exploiting reflector cluster configurations
            
        1.7.2 Reflection Path Manipulation
            1.7.2.1 Altering paths through reflector hierarchies
            1.7.2.2 Creating routing inconsistencies via reflection
            1.7.2.3 Exploiting reflection for path hiding
            
    1.8 Aggregation and Deaggregation Attacks [OR]
    
        1.8.1 Route Aggregation Abuse
            1.8.1.1 Creating overly broad aggregate announcements
            1.8.1.2 Aggregating unauthorized prefixes
            1.8.1.3 Using aggregation to hide more specific routes
            
        1.8.2 Deaggregation Attacks
            1.8.2.1 Announcing deaggregated routes for hijacking
            1.8.2.2 Creating route fragmentation through deaggregation
            1.8.2.3 Exploiting deaggregation for traffic interception
```

## Why it works

-   Trust-Based Protocol: BGP operates on mutual trust between peers without inherent authentication
-   Attribute Flexibility: BGP's extensive attribute set provides multiple manipulation vectors
-   Global Scale: Internet routing complexity makes detection difficult
-   Slow Convergence: BGP's slow convergence allows malicious paths to persist
-   Implementation Variability: Different vendor implementations handle attributes inconsistently
-   Limited Validation: Many networks lack comprehensive path validation mechanisms

## Mitigation

### BGP Path Validation
-   Action: Implement path validation using RPKI and BGPsec
-   How:
    -   Deploy RPKI for route origin validation
    -   Implement BGPsec for path validation where supported
    -   Use AS_PATH verification tools and services
-   Configuration Example (BGPsec, cisco):

```text
router bgp 65001
 bgp sec enabled
 neighbor 192.0.2.1 bgpsec enable
```

### Attribute filtering policies
-   Action: Implement strict attribute filtering and validation
-   How:
    -   Filter unexpected AS_PATH segments
    -   Validate community attributes against policy
    -   Sanitize MED values from external peers
-   Configuration example:

```text
route-map EXTERNAL-IN permit 10
 match as-path 100
 set community no-export
ip as-path access-list 100 deny _65500_
```

### Route monitoring and analysis
-   Action: Continuously monitor BGP paths for anomalies
-   How:
    -   Implement BGP monitoring tools (BGPStream, ExaBGP)
    -   Set up real-time alerting for path changes
    -   Conduct regular path analysis and auditing
-   Tools: BGPMon, RIPE Stat, and commercial monitoring solutions

### Peer authentication and validation
-   Action: Strengthen BGP peer authentication and validation
-   How:
    -   Implement BGP MD5 authentication
    -   Validate peer AS numbers and prefixes
    -   Use prefix limits and rate limiting
-   Configuration example:

```text
neighbor 192.0.2.1 password BGP-P@ssw0rd
neighbor 192.0.2.1 maximum-prefix 1000
```

### Traffic engineering controls
-   Action: Implement controls for legitimate traffic engineering
-   How:
    -   Document and audit all traffic engineering changes
    -   Implement change control procedures
    -   Monitor for unauthorized engineering activities
-   Best Practice: Maintain traffic engineering documentation

### Incident response planning
-   Action: Develop specific response procedures for path manipulation
-   How:
    -   Create incident response playbooks for BGP incidents
    -   Establish communication channels with peers
    -   Practice path manipulation response scenarios
-   Template: Maintain updated contact lists and procedures

### MANRS Compliance
-   Action: Implement Mutually Agreed Norms for Routing Security
-   How:
    -   Participate in MANRS initiative
    -   Implement MANRS actions for network operators
    -   Promote MANRS adoption among peers
-   Benefits: Improved routing security and industry collaboration