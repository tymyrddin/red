# ICMP-based service discovery

## Attack pattern

ICMP-based service discovery encompasses techniques that leverage the Internet Control Message Protocol to 
identify active hosts, map network services, and gather intelligence about target environments. These methods 
exploit both legacy ICMP features and modern protocol implementations to conduct reconnaissance while potentially 
evading detection mechanisms focused on more conventional scanning techniques.

```text
1. ICMP-based service discovery [OR]

    1.1 Legacy ICMP exploitation [OR]
    
        1.1.1 ICMP timestamp request abuse
            1.1.1.1 Operating system fingerprinting via timestamp responses
            1.1.1.2 System clock analysis for host identification
            1.1.1.3 Timezone detection through timestamp analysis
            1.1.1.4 Host availability verification through timestamp replies
            
        1.1.2 ICMP address mask request probing
            1.1.2.1 Subnet mask discovery for network mapping
            1.1.2.2 Network class identification through mask responses
            1.1.2.3 Broadcast address calculation for attack planning
            1.1.2.4 Router interface identification via mask responses
            
        1.1.3 Information request exploitation
            1.1.3.1 Host discovery through information request probing
            1.1.3.2 System identification via information response patterns
            1.1.3.3 Network mapping using information request responses
            1.1.3.4 Security control bypass through legacy protocol abuse
            
    1.2 IPv6-specific discovery [OR]
    
        1.2.1 ICMPv6 router solicitation scanning
            1.2.1.1 Active router discovery through solicited advertisements
            1.2.1.2 Router capability profiling through advertisement analysis
            1.2.1.3 Network parameter extraction from RA messages
            1.2.1.4 Default gateway identification through forced advertisements
            
        1.2.2 Multicast listener discovery queries
            1.2.2.1 Host identification through multicast group membership
            1.2.2.2 Service discovery via multicast listener queries
            1.2.2.3 Application fingerprinting through group membership patterns
            1.2.2.4 Network device identification via multicast responses
            
        1.2.3 Neighbour advertisement spoofing
            1.2.3.1 Neighbour cache poisoning through malicious advertisements
            1.2.3.2 Host presence detection through neighbour discovery
            1.2.3.3 Address assignment pattern analysis
            1.2.3.4 Duplicate address detection exploitation
            
    1.3 Cloud environment mapping [OR]
    
        1.3.1 ICMP-based cloud provider identification
            1.3.1.1 TTL-based cloud fingerprinting for provider identification
            1.3.1.2 Response time analysis for geographic region mapping
            1.3.1.3 Cloud-specific TCP/IP stack fingerprinting
            1.3.1.4 Metadata service reachability testing via ICMP
            
        1.3.2 VPC/VNet boundary discovery
            1.3.2.1 Virtual network segmentation mapping through ICMP probing
            1.3.2.2 Network ACL and security group rule deduction
            1.3.2.3 Peering connection identification through routing analysis
            1.3.2.4 Internet gateway and NAT gateway identification
            
        1.3.3 Container network mapping via ICMP
            1.3.3.1 Kubernetes cluster discovery through ICMP patterns
            1.3.3.2 Pod and service discovery within container networks
            1.3.3.3 Container network interface detection
            1.3.3.4 Service mesh infrastructure identification
            
    1.4 Protocol variation techniques [OR]
    
        1.4.1 ICMP type and code manipulation
            1.4.1.1 Uncommon ICMP type usage for service detection
            1.4.1.2 Code field variation for response analysis
            1.4.1.3 Type manipulation to evade signature detection
            1.4.1.4 Protocol compliance testing through ICMP variations
            
        1.4.2 Error message exploitation
            1.4.2.1 Destination unreachable message analysis for service discovery
            1.4.2.2 Time exceeded message examination for path analysis
            1.4.2.3 Parameter problem message inspection for system profiling
            1.4.2.4 Source quench message analysis for service identification
            
    1.5 Stealth and evasion techniques [OR]
    
        1.5.1 Low-rate discovery methods
            1.5.1.1 Sub-threshold ICMP probing to evade detection
            1.5.1.2 Time-distributed discovery over extended periods
            1.5.1.3 Randomised probe timing for pattern avoidance
            1.5.1.4 Burst probing during high network activity periods
            
        1.5.2 Source obfuscation methods
            1.5.2.1 Source address rotation through compromised hosts
            1.5.2.2 IP spoofing for attribution evasion
            1.5.2.3 Proxy chain utilisation for anonymity
            1.5.2.4 Cloud instance abuse for source diversity
            
    1.6 Response analysis and correlation [OR]
    
        1.6.1 Timing-based analysis
            1.6.1.1 Response time measurement for system identification
            1.6.1.2 Network latency analysis for topology mapping
            1.6.1.3 Jitter analysis for network condition assessment
            1.6.1.4 Round-trip time calculation for distance estimation
            
        1.6.2 Behavioural fingerprinting
            1.6.2.1 Implementation-specific response analysis
            1.6.2.2 Protocol stack fingerprinting through ICMP behaviour
            1.6.2.3 Device type classification via response patterns
            1.6.2.4 Service identification through error message analysis
```

## Why it works

-   Protocol necessity: ICMP is essential for network operations and cannot be completely blocked
-   Legacy support: Many systems maintain support for deprecated ICMP features
-   Monitoring gaps: Security systems often focus on TCP/UDP while overlooking ICMP
-   Protocol complexity: ICMPv6 introduces numerous new features and attack surfaces
-   Cloud exposure: Cloud environments have unique characteristics that can be fingerprinted
-   Evasion capabilities: ICMP discovery can bypass traditional port scanning detection

## Counter moves

ICMP-based service discovery is what this page works through. Filtering and rate-limiting ICMP, and watching for tunnelling, are the counters. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
