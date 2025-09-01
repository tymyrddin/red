# Advanced persistence mechanisms

## Attack pattern

Advanced persistence mechanisms represent sophisticated techniques that adversaries employ to maintain long-term access and influence within network routing infrastructure while evading detection. These attacks focus on stealthy manipulation of routing information, exploitation of protocol ambiguities, and adaptive timing to avoid security monitoring systems. By leveraging subtle and temporary manipulations, attackers can achieve their objectives without triggering conventional security alerts.

```text
1. Advanced persistence mechanisms [OR]

    1.1 Stealthy route manipulation [OR]
    
        1.1.1 Time-based hijacking (short-lived attacks)
            1.1.1.1 Micro-duration route announcements (seconds to minutes)
            1.1.1.2 Rapid announce-withdraw cycles to avoid detection
            1.1.1.3 Scheduled attacks during low-monitoring periods
            1.1.1.4 Transient route manipulation for specific transactions
            
        1.1.2 Geographic-specific route manipulation
            1.1.2.1 Regional prefix hijacking targeting specific locations
            1.1.2.2 AS-path prepending for traffic engineering evasion
            1.1.2.3 Selective advertisement based on geolocation
            1.1.2.4 Localised routing table poisoning
            
        1.1.3 Mimicking legitimate AS-path patterns
            1.1.3.1 Copying valid AS-path structures and sequences
            1.1.3.2 Modelling legitimate routing behaviour patterns
            1.1.3.3 Replicating common transit provider patterns
            1.1.3.4 Emulating peer relationship characteristics
            
    1.2 Detection evasion [OR]
    
        1.2.1 Abuse of resource public key infrastructure 'unknown' state
            1.2.1.1 Exploitation of unverified route origin authorisations
            1.2.1.2 Manipulation of RPKI validation cache timing
            1.2.1.3 Targeting prefixes with incomplete RPKI deployment
            1.2.1.4 Exploiting validation result interpretation ambiguities
            
        1.2.2 Leveraging peer conflicts for ambiguity
            1.2.2.1 Exploiting multi-homed network inconsistencies
            1.2.2.2 Creating routing contradictions between peers
            1.2.2.3 Utilising partial routing information propagation
            1.2.2.4 Amplifying existing routing policy conflicts
            
        1.2.3 Adaptive attack timing based on network monitoring
            1.2.3.1 Reconnaissance of monitoring system patterns and gaps
            1.2.3.2 Synchronisation with monitoring system maintenance windows
            1.2.3.3 Attack pacing below detection thresholds
            1.2.3.4 Exploitation of alert fatigue and response times
            
    1.3 Persistence through infrastructure compromise [OR]
    
        1.3.1 Long-term router residency
            1.3.1.1 Firm-level implants in network devices
            1.3.1.2 Persistent malware in routing engine memory
            1.3.1.3 Configuration backdoors and hidden access methods
            1.3.1.4 Compromised software updates and maintenance channels
            
        1.3.2 Supply chain persistence
            1.3.2.1 Hardware implants in networking equipment
            1.3.2.2 Compromised firmware distribution mechanisms
            1.3.2.3 Malicious code in vendor software updates
            1.3.2.4 Backdoored management tools and utilities
            
        1.3.3 Operational compromise
            1.3.3.1 Credential theft and reuse across systems
            1.3.3.2 Compromise of network management systems
            1.3.3.3 Exploitation of remote access infrastructure
            1.3.3.4 Social engineering of network operations staff
            
    1.4 Protocol abuse for persistence [OR]
    
        1.4.1 BGP session manipulation
            1.4.1.1 Persistent session establishment without authentication
            1.4.1.2 Exploitation of session recovery mechanisms
            1.4.1.3 Manipulation of keepalive and hold timer mechanisms
            1.4.1.4 Abuse of graceful restart functionality
            
        1.4.2 Route flap exploitation
            1.4.2.1 Controlled route flapping to avoid pattern detection
            1.4.2.2 Exploitation of dampening threshold configurations
            1.4.2.3 Manipulation of route stability metrics
            1.4.2.4 Abuse of minimum route advertisement intervals
            
        1.4.3 Community attribute manipulation
            1.4.3.1 Unauthorised use of recognised community values
            1.4.3.2 Creation of custom communities for traffic manipulation
            1.4.3.3 Exploitation of community-based filtering gaps
            1.4.3.4 Persistence through community attribute propagation
```

## Why it works

-   Monitoring limitations: Many detection systems have blind spots for short-lived or low-volume anomalies
-   Protocol complexities: BGP's flexibility and complexity create opportunities for subtle manipulation
-   Validation gaps: Incomplete RPKI deployment and validation allows exploitation of 'unknown' states
-   Human factors: Alert fatigue and operational pressures reduce effectiveness of manual monitoring
-   System latency: Detection and response systems often have inherent delays that can be exploited
-   Trust relationships: Existing peering relationships can be abused to lend credibility to malicious routes
-   Scale challenges: The global routing table's size makes comprehensive monitoring difficult

## Mitigation

### Enhanced monitoring and detection

-   Action: Implement advanced monitoring capabilities for stealthy routing attacks
-   How:
    -   Deploy high-resolution routing data collection systems
    -   Implement machine learning-based anomaly detection
    -   Use real-time streaming analytics for route changes
    -   Establish comprehensive baseline behaviour profiles
-   Configuration example (Advanced monitoring):

```text
monitoring enhancement
 data-collection
  streaming-bgp-updates enabled
  high-resolution-timing enabled
 anomaly-detection
  machine-learning-enabled
  real-time-analysis enabled
 baseline-profiling
  continuous-learning enabled
  adaptive-thresholds enabled
```

### Resource public key infrastructure deployment

-   Action: Comprehensively deploy and enforce RPKI validation
-   How:
    -   Implement RPKI origin validation on all border routers
-   RPKI deployment framework:

```text
rpki deployment
 origin-validation
  enforcement strict
  invalid-handling reject
 rov-implementation
  all-bgp-sessions enabled
  logging detailed
 maintenance
  cache-update-frequency 300
  validation-check-interval 60
```

### Route filtering and validation

-   Action: Implement robust route filtering and validation policies
-   How:
    -   Deploy prefix lists and route maps for all peerings
    -   Implement maximum prefix limits per session
    -   Use AS-path filters and regular expression matching
    -   Establish consistent filtering policies across all peers
-   Filtering policy example:

```text
route-filtering policy
 prefix-validation
  max-prefix-limit enabled
  as-path-filtering strict
 peer-validation
  inbound-policy consistent
  outbound-policy validated
 maintenance
  regular-policy-review enabled
  automatic-update-checking enabled
```

### Operational security enhancement

-   Action: Strengthen operational security practices and procedures
-   How:
    -   Implement multi-factor authentication for all management access
    -   Conduct regular security training for operations staff
    -   Establish change management and peer review processes
    -   Maintain comprehensive audit logging and monitoring
-   Operational security framework:

```text
operational-security
 access-control
  multi-factor-authentication required
  privilege-separation enforced
 procedures
  change-management required
  peer-review enabled
 auditing
  comprehensive-logging enabled
  regular-audits scheduled
```

### Incident response readiness

-   Action: Maintain readiness for responding to persistent routing attacks
-   How:
    -   Develop and practice incident response playbooks
    -   Establish communication channels with peers and providers
    -   Implement rapid route filtering and mitigation capabilities
    -   Maintain forensic capabilities for attack analysis
-   Response readiness configuration:

```text
incident-response
 preparedness
  playbooks-maintained updated
  regular-exercises scheduled
 communication
  peer-coordination-channels established
  provider-escalation-paths defined
 mitigation
  rapid-filtering-capability tested
  backup-connectivity available
```

## Key insights from real-world implementations

-   Detection latency: Many organisations discover attacks only after significant damage has occurred
-   Resource constraints: Comprehensive monitoring requires substantial resources and expertise
-   Coordination challenges: Effective response often requires coordination across multiple organisations
-   Evolution pace: Attack techniques evolve faster than defensive measures can be implemented
-   Visibility gaps: Many networks lack complete visibility into their routing ecosystem

## Future trends and recommendations

-   Automated defence: Development of AI-powered defence systems for routing security
-   Collaborative defence: Enhanced information sharing and coordinated response mechanisms
-   Protocol improvements: Evolution of BGP security extensions and implementations
-   Regulatory frameworks: Development of industry standards and compliance requirements
-   Continuous education: Ongoing training and awareness programmes for network operators

## Conclusion

Advanced persistence mechanisms represent a significant and evolving threat to internet routing infrastructure. These attacks leverage sophisticated techniques to maintain long-term access and influence while evading conventional detection methods. Defence requires a comprehensive approach including advanced monitoring capabilities, robust validation mechanisms, strong operational security practices, and coordinated incident response. As attack techniques continue to evolve, organisations must maintain vigilance through continuous investment in security capabilities, regular training and exercises, and active participation in industry-wide security initiatives. The protection of routing infrastructure demands ongoing adaptation and improvement of security measures to address these persistent and sophisticated threats.
