# Dual-stack attacks (IPv4 and IPv6)

## Attack pattern

Dual-stack networks, which run both IPv4 and IPv6 simultaneously, introduce unique attack vectors where 
vulnerabilities in one protocol can be exploited to attack the other, or where attackers can bypass security 
controls by leveraging the less-secured protocol path. The complexity of managing two protocol stacks doubles 
the attack surface and introduces transition-related vulnerabilities.

```text
1. Dual-stack attacks [OR]

    1.1 Protocol preference exploitation [OR]
    
        1.1.1 IPv6 priority bypass
            1.1.1.1 Exploiting happy eyeballs algorithms to force IPv6 preference
            1.1.1.2 Using IPv6-only features to bypass IPv4-specific security controls
            1.1.1.3 Manipulating DNS responses (AAAA vs. A records) to control protocol selection
            
        1.1.2 Fallback manipulation
            1.1.2.1 Deliberately causing IPv6 failures to force fallback to vulnerable IPv4 paths
            1.1.2.2 Timing attacks to disrupt protocol negotiation
            1.1.2.3 DNS cache poisoning to influence protocol selection
            
    1.2 Asymmetric security bypass [OR]
    
        1.2.1 Differential security policies
            1.2.1.1 Exploiting gaps between IPv4 and IPv6 firewall rules
            1.2.1.2 Bypassing IPv4-only IDS/IPS systems via IPv6 paths
            1.2.1.3 Leveraging inconsistent security group configurations across protocols
            
        1.2.2 Monitoring evasion
            1.2.2.1 Using IPv6 for stealth where IPv4 monitoring is more robust
            1.2.2.2 Exploiting lack of IPv6 logging and audit capabilities
            1.2.2.3 Avoiding detection by switching protocols mid-session
            
    1.3 Transition mechanism exploitation [OR]
    
        1.3.1 Tunnelling abuse
            1.3.1.1 Exploiting 6to4, Teredo, or ISATAP tunnels for evasion
            1.3.1.2 Using tunnels to bypass network perimeter controls
            1.3.1.3 Embedding malicious payloads in tunnelled traffic
            
        1.3.2 Translation attacks
            1.3.2.1 NAT64/DNS64 manipulation for traffic interception
            1.3.2.2 Protocol translation vulnerabilities causing state inconsistencies
            1.3.2.3 Stateless IP/ICMP translation (SIIT) exploits
            
    1.4 Address spoofing and manipulation [OR]
    
        1.4.1 Cross-protocol spoofing
            1.4.1.1 Using IPv6 to spoof IPv4 addresses or vice versa
            1.4.1.2 Exploiting address mapping mechanisms in transition technologies
            1.4.1.3 Forging addresses to bypass protocol-specific authentication
            
        1.4.2 DNS-based attacks
            1.4.2.1 AAAA record poisoning to redirect IPv6 traffic
            1.4.2.2 DNS64 manipulation for translation attacks
            1.4.2.3 Double DNS poisoning affecting both protocol stacks
            
    1.5 Resource exhaustion [OR]
    
        1.5.1 Double-stack resource consumption
            1.5.1.1 Attacking both protocol stacks simultaneously to maximise impact
            1.5.1.2 Exploiting dual-stack memory and CPU overhead
            1.5.1.3 Caching attacks against both IPv4 and IPv6 resolution systems
            
        1.5.2 State table attacks
            1.5.2.1 Exhausting connection tracking resources for both protocols
            1.5.2.2 Double SYN flooding against dual-stack services
            1.5.2.3 Exploiting NAT44 and NAT64 simultaneously
            
    1.6 Application layer attacks [OR]
    
        1.6.1 Cross-protocol application exploits
            1.6.1.1 Different application behaviour over IPv4 vs IPv6
            1.6.1.2 Protocol-specific application vulnerabilities
            1.6.1.3 Authentication bypass through protocol switching
            
        1.6.2 API exploitation
            1.6.2.1 Socket API differences between IPv4 and IPv6
            1.6.2.2 Address family conversion vulnerabilities
            1.6.2.3 getaddrinfo() behaviour exploitation
            
    1.7 Operating system exploits [OR]
    
        1.7.1 Dual-stack implementation flaws
            1.7.1.1 Kernel vulnerabilities in dual-stack handling
            1.7.1.2 Memory corruption in protocol transition code
            1.7.1.3 Race conditions between IPv4 and IPv6 paths
            
        1.7.2 Stack preference vulnerabilities
            1.7.2.1 OS-specific protocol selection algorithms
            1.7.2.2 Source address selection vulnerabilities
            1.7.2.3 Route table manipulation across protocols
            
    1.8 Network infrastructure attacks [OR]
    
        1.8.1 Router and switch exploitation
            1.8.1.1 Dual-stack control plane attacks
            1.8.1.2 Memory exhaustion on network devices
            1.8.1.3 CPU overload from processing both protocols
            
        1.8.2 Load balancer attacks
            1.8.2.1 Protocol-specific load balancing bypass
            1.8.2.2 Persistence mechanism manipulation
            1.8.2.3 Health check exploitation across protocols
            
    1.9 Cloud and virtualisation [OR]
    
        1.9.1 Multi-protocol SDN exploits
            1.9.1.1 Controller manipulation through either protocol
            1.9.1.2 Flow rule conflicts between IPv4 and IPv6
            1.9.1.3 Virtual switch double-stack vulnerabilities
            
        1.9.2 Cloud provider specific attacks
            1.9.2.1 Exploiting differences in cloud IPv4 vs IPv6 implementation
            1.9.2.2 Bypassing cloud security groups through protocol selection
            1.9.2.3 Cross-protocol attacks in multi-tenant environments
            
    1.10 Advanced persistence [OR]
    
        1.10.1 Cross-protocol C2 channels
            1.10.1.1 Using both protocols for redundant command channels
            1.10.1.2 Protocol switching to evade detection
            1.10.1.3 IPv6 for persistence where IPv4 is monitored
            
        1.10.2 Double stack backdoors
            1.10.2.1 Maintaining access through both protocol paths
            1.10.2.2 Fallback mechanisms using alternative protocol
            1.10.2.3 Cross-protocol wake-up mechanisms
```

## Why it works

-   Asymmetric security: Organisations often implement stronger security for IPv4 than IPv6, creating weak points
-   Implementation complexity: Managing two protocols increases configuration errors and oversight opportunities
-   Transition mechanisms: Tunnelling and translation technologies introduce additional attack surfaces
-   Monitoring gaps: Many organisations monitor IPv4 heavily but neglect IPv6 traffic
-   Protocol differences: Varying features and behaviours create opportunities for exploitation

## Counter moves

Dual-stack attacks (IPv4 and IPv6) is the case here. Anti-spoofing filters such as BCP 38, and segmentation, close it. The defender's view is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
