# ICMPv6 router advertisement spoofing

## Attack pattern

ICMPv6 Router Advertisement spoofing represents a critical attack vector in IPv6 networks that exploits the Neighbour Discovery Protocol to manipulate network configuration and traffic routing. These attacks allow malicious actors to impersonate legitimate routers, poison network caches, and manipulate address configuration, leading to man-in-the-middle attacks, traffic interception, and network disruption.

```text
1. ICMPv6 router advertisement spoofing [AND]

    1.1 Rogue RA attacks [OR]
    
        1.1.1 Default gateway impersonation
            1.1.1.1 Fake router advertisement transmission
            1.1.1.2 Router priority manipulation for preferred status
            1.1.1.3 Lifetime field spoofing for persistence
            1.1.1.4 Multiple rogue router coordination
            
        1.1.2 DNS server injection via RAs
            1.1.2.1 RDNSS (recursive DNS server) option abuse
            1.1.2.2 DNS search list option manipulation
            1.1.2.3 DNSSL (DNS search list) option spoofing
            1.1.2.4 DNS configuration override attacks
            
        1.1.3 Route preference manipulation
            1.1.3.1 Route information option exploitation
            1.1.3.2 Prefix preference manipulation
            1.1.3.3 Default route preference spoofing
            1.1.3.4 Multi-homing environment exploitation
            
    1.2 Neighbour discovery exploitation [OR]
    
        1.2.1 Weak IPv6 neighbour discovery abuse
            1.2.1.1 Unsolicited neighbour advertisement spoofing
            1.2.1.2 Neighbour solicitation response manipulation
            1.2.1.3 Address resolution protocol attacks
            1.2.1.4 Redirect message exploitation
            
        1.2.2 Duplicate address detection spoofing
            1.2.2.1 DAD process interception and manipulation
            1.2.2.2 Address conflict induction attacks
            1.2.2.3 Tentative address reservation exploitation
            1.2.2.4 Address assignment disruption
            
        1.2.3 Neighbour cache poisoning
            1.2.3.1 Cache entry corruption through spoofed advertisements
            1.2.3.2 Stale entry exploitation for man-in-the-middle
            1.2.3.3 Cache overflow attacks through rapid advertisements
            1.2.3.4 Invalid entry insertion for service disruption
            
    1.3 SLAAC attacks [OR]
    
        1.3.1 IPv6 address configuration manipulation
            1.3.1.1 Prefix information option spoofing
            1.3.1.2 Address autoconfiguration hijacking
            1.3.1.3 Valid lifetime field manipulation
            1.3.1.4 Preferred lifetime field exploitation
            
        1.3.2 Privacy extension exploitation
            1.3.2.1 Temporary address generation prediction
            1.3.2.2 Privacy address correlation attacks
            1.3.2.3 Stable privacy identifier exploitation
            1.3.2.4 Address generation algorithm manipulation
            
        1.3.3 Temporary address collision attacks
            1.3.3.1 Temporary address space exhaustion
            1.3.3.2 Address collision induction for disruption
            1.3.3.3 Privacy address conflict attacks
            1.3.3.4 Generation counter manipulation
            
    1.4 MitM and interception techniques [OR]
    
        1.4.1 Traffic redirection attacks
            1.4.1.1 Redirect message spoofing for path manipulation
            1.4.1.2 Next-hop manipulation through RA options
            1.4.1.3 Route optimisation exploitation
            1.4.1.4 Traffic tunnelling through rogue routers
            
        1.4.2 Packet interception methods
            1.4.2.1 On-link prefix spoofing for local interception
            1.4.2.2 Off-link prefix advertisement for traffic capture
            1.4.2.3 Default route hijacking for comprehensive interception
            1.4.2.4 Selective route advertisement for targeted capture
            
    1.5 Persistence and evasion [OR]
    
        1.5.1 Persistent rogue router techniques
            1.5.1.1 Regular advertisement transmission for maintenance
            1.5.1.2 Lifetime field manipulation for continued presence
            1.5.1.3 Multiple advertisement source rotation
            1.5.1.4 Evasion through legitimate-looking pattern mimicry
            
        1.5.2 Detection avoidance methods
            1.5.2.1 Rate limiting compliance to avoid anomaly detection
            1.5.2.2 Valid checksum maintenance for protocol compliance
            1.5.2.3 Source address spoofing for attribution evasion
            1.5.2.4 Timing randomisation for pattern avoidance
            
    1.6 Network disruption attacks [OR]
    
        1.6.1 Service disruption techniques
            1.6.1.1 Default router list corruption
            1.6.1.2 Prefix information invalidation
            1.6.1.3 DNS configuration destruction
            1.6.1.4 Parameter spoofing for system misconfiguration
            
        1.6.2 Resource exhaustion attacks
            1.6.2.1 Neighbour cache overflow through rapid advertisements
            1.6.2.2 Processor exhaustion through complex RA processing
            1.6.2.3 Memory consumption through large option fields
            1.6.2.4 Network bandwidth consumption through advertisement floods
```

## Why it works

-   Protocol design limitations: IPv6 neighbour discovery lacks built-in authentication in basic implementations
-   Trust assumptions: Hosts typically trust router advertisements without verification
-   Network necessity: Router advertisements are essential for IPv6 network operation
-   Monitoring gaps: Many networks lack adequate RA guard protection
-   Configuration complexity: Proper RA protection requires specific switch configuration
-   Protocol flexibility: ICMPv6's extensible options provide multiple attack vectors

## Mitigation

### RA guard implementation

-   Action: Deploy router advertisement guard on layer 2 switches
-   How:
    -   Configure RA guard on all user-facing switch ports
    -   Implement RA guard policies for different port types
    -   Use device role classification for appropriate RA handling
    -   Regularly update and audit RA guard configurations
-   Best practice: Enable RA guard on all access ports to prevent rogue advertisements

### Secure neighbour discovery

-   Action: Implement secure neighbour discovery (SEND) where supported
-   How:
    -   Deploy SEND for cryptographically verified router advertisements
    -   Use certificate-based router authentication
    -   Implement timestamp protection against replay attacks
    -   Configure nonce-based protection for neighbour discovery
-   Best practice: Use SEND in high-security environments where supported

### Network segmentation

-   Action: Implement proper network segmentation
-   How:
    -   Segment networks to limit broadcast domain sizes
    -   Use private VLANs to restrict layer 2 communication
    -   Implement router ACLs to control RA propagation
    -   Deploy firewalls between network segments
-   Best practice: Limit the scope of router advertisement propagation

### Monitoring and detection

-   Action: Deploy comprehensive monitoring for RA spoofing
-   How:
    -   Implement network monitoring for rogue RA detection
    -   Use intrusion detection systems with RA spoofing signatures
    -   Monitor for multiple routers on segments where only one should exist
    -   Deploy anomaly detection for unusual RA patterns
-   Best practice: Continuous monitoring with real-time alerting

### Host hardening

-   Action: Harden hosts against RA spoofing attacks
-   How:
    -   Configure hosts to ignore RAs on unauthorised ports
    -   Implement host-based firewall rules for ICMPv6
    -   Use static routing where appropriate
    -   Regularly update and patch operating systems
-   Best practice: Defence in depth with host-based protections

## Key insights from real-world attacks

-   RA spoofing remains prevalent: Many organisations still lack adequate RA protection
-   Switch configuration gaps: RA guard is often not properly configured or enabled
-   Cloud environment vulnerability: Virtual networks are particularly susceptible to RA attacks
-   IoT device exploitation: Constrained devices often lack proper RA protection

## Future trends and recommendations

-   Increasing automation: Tools will make RA spoofing attacks more accessible
-   Cloud targeting: More attacks will focus on cloud and virtualised environments
-   Protocol evolution: IPv6 enhancements may introduce new protection mechanisms
-   Detection improvement: Advanced monitoring will become essential for RA protection

## Conclusion

ICMPv6 Router Advertisement spoofing represents a significant threat to IPv6 network security, enabling attackers to manipulate network configuration, redirect traffic, and conduct man-in-the-middle attacks. These attacks exploit the trust-based nature of neighbour discovery protocol and the necessity of router advertisements for IPv6 operation. Defence requires a multi-layered approach including RA guard implementation, secure neighbour discovery, network segmentation, comprehensive monitoring, and host hardening. As IPv6 adoption continues to grow and networks become more complex, organisations must prioritise protection against RA spoofing attacks. The future of IPv6 security will depend on proper implementation of RA protection mechanisms and continuous vigilance against evolving attack techniques.
