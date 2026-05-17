# NAT/Firewall bypass techniques

## Attack pattern

NAT and firewall bypass techniques leverage the fundamental requirements of ICMP for network operations to establish 
covert channels and evade security controls. These methods exploit the necessary nature of certain ICMP messages, 
protocol complexities, and stateful inspection limitations to circumvent network perimeter defences and maintain 
persistent access.

```text
1. NAT/firewall bypass [AND]

    1.1 Callback mechanisms [OR]
    
        1.1.1 ICMP echo reply callback channels
            1.1.1.1 Outbound-initiated echo request triggering inbound replies
            1.1.1.2 Payload encoding in echo reply messages
            1.1.1.3 Beaconing through regular echo request messages
            1.1.1.4 Covert channel establishment using echo timing
            
        1.1.2 ICMPv6 informational message abuse
            1.1.2.1 Router advertisement message exploitation
            1.1.2.2 Neighbour advertisement callback channels
            1.1.2.3 Multicast listener discovery message abuse
            1.1.2.4 Parameter problem message exploitation
            
        1.1.3 Router solicitation callbacks
            1.1.3.1 Forced router advertisement generation
            1.1.3.2 Router preference manipulation for response triggering
            1.1.3.3 Prefix information exfiltration through router advertisements
            1.1.3.4 Timing attacks through solicitation storms
            
    1.2 Whitelist exploitation [OR]
    
        1.2.1 PMTUD (path MTU discovery) abuse
            1.2.1.1 Fake packet too big message generation
            1.2.1.2 MTU discovery process manipulation
            1.2.1.3 Path MTU cache poisoning attacks
            1.2.1.4 ICMPv6 packet too big message exploitation
            
        1.2.2 ICMP error message whitelist bypass
            1.2.2.1 Destination unreachable message abuse
            1.2.2.2 Time exceeded message exploitation
            1.2.2.3 Parameter problem message manipulation
            1.2.2.4 Source quench message abuse (where supported)
            
        1.2.3 IPv6 required ICMPv6 type exploitation
            1.2.3.1 Neighbour discovery protocol requirement abuse
            1.2.3.2 Multicast listener discovery necessity exploitation
            1.2.3.3 Router discovery process manipulation
            1.2.3.4 Error message requirement compliance abuse
            
    1.3 Stateful firewall evasion [OR]
    
        1.3.1 ICMP session table manipulation
            1.3.1.1 Session state exhaustion through rapid ICMP messages
            1.3.1.2 Session table entry corruption
            1.3.1.3 State tracking bypass through ICMP type variation
            1.3.1.4 Query/response state machine manipulation
            
        1.3.2 Timeout exploitation for persistence
            1.3.2.1 Session timeout extension through keep-alive messages
            1.3.2.2 Low-frequency communication to avoid idle timeouts
            1.3.2.3 Timing attacks against stateful inspection timeouts
            1.3.2.4 Persistent session maintenance through regular beacons
            
        1.3.3 Fragment-based state table attacks
            1.3.3.1 Fragment reassembly state exhaustion
            1.3.3.2 Overlapping fragment state table corruption
            1.3.3.3 Fragment timeout manipulation
            1.3.3.4 Atomic fragment exploitation in IPv6
            
    1.4 Protocol compliance attacks [OR]
    
        1.4.1 Standards-compliant evasion
            1.4.1.1 RFC-compliant but unusual ICMP usage
            1.4.1.2 Optional feature exploitation for bypass
            1.4.1.3 Protocol extension abuse for evasion
            1.4.1.4 Implementation-specific interpretation differences
            
        1.4.2 Multi-protocol bypass techniques
            1.4.2.1 ICMP-triggered protocol activation
            1.4.2.2 Protocol switching based on network conditions
            1.4.2.3 Fallback mechanism exploitation
            1.4.2.4 Protocol tunnel establishment through ICMP
            
    1.5 Network address translation exploitation [OR]
    
        1.5.1 NAT state table manipulation
            1.5.1.1 NAT binding exhaustion through ICMP messages
            1.5.1.2 Translation table corruption attacks
            1.5.1.3 Port allocation mechanism exploitation
            1.5.1.4 NAT timeout extension techniques
            
        1.5.2 NAT traversal techniques
            1.5.2.1 ICMP-based NAT penetration methods
            1.5.2.2 Port prediction through ICMP analysis
            1.5.2.3 NAT behaviour fingerprinting through ICMP
            1.5.2.4 Hairpinning exploitation through ICMP messages
            
    1.6 Application layer gateway evasion [OR]
    
        1.6.1 ALG bypass techniques
            1.6.1.1 ICMP message structure manipulation to evade ALG inspection
            1.6.1.2 Protocol confusion attacks against ALGs
            1.6.1.3 ALG resource exhaustion through complex ICMP messages
            1.6.1.4 Application layer gateway timeout exploitation
            
        1.6.2 Deep packet inspection evasion
            1.6.2.1 Payload obfuscation to evade content inspection
            1.6.2.2 Encryption of ICMP payload contents
            1.6.2.3 Protocol tunnelling within ICMP messages
            1.6.2.4 Content encoding to avoid signature detection
```

## Why it works

-   Protocol necessity: ICMP is required for proper network operation and cannot be completely blocked
-   Stateful inspection challenges: ICMP's connectionless nature makes state tracking difficult
-   Whitelist requirements: Certain ICMP types are required for basic network functionality and cannot be blocked outright
-   Implementation inconsistencies: Different devices handle ICMP differently, creating bypass opportunities
-   Performance considerations: Deep ICMP inspection can be computationally expensive
-   Legacy rule sets: Many firewall configurations have overly permissive ICMP rules
