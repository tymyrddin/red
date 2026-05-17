# SLAAC & RA attacks (IPv6)

## Attack pattern

The Stateless Address Autoconfiguration (SLAAC) and Router Advertisement (RA) mechanisms in IPv6 are critical for 
automatic address assignment and network configuration. However, their lack of inherent authentication makes them 
vulnerable to exploitation. Attackers can spoof RA messages to manipulate network behaviour, leading to 
man-in-the-middle (MitM) attacks, traffic interception, and network disruption.

```text
1. Slaac & ra attacks [OR]

    1.1 Rogue router advertisement (RA) attacks [OR]
    
        1.1.1 Default gateway spoofing
            1.1.1.1 Advertising malicious IPv6 router as default gateway
            1.1.1.2 Redirecting traffic through attacker-controlled paths
            
        1.1.2 DNS server spoofing (RDNSS)
            1.1.2.1 Injecting rogue DNS server addresses via RA options
            1.1.2.2 Hijacking DNS resolution for malicious redirects
            
        1.1.3 Prefix spoofing
            1.1.3.1 Advertising fraudulent IPv6 prefixes
            1.1.3.2 Forcing hosts to generate addresses from malicious prefixes
            
    1.2 Denial-of-service (DoS) [OR]
    
        1.2.1 RA flooding
            1.2.1.1 Overwhelming networks with spoofed RA packets
            1.2.1.2 Disrupting legitimate router advertisements
            
        1.2.2 Duplicate address detection (DAD) exploitation
            1.2.2.1 Triggering address conflicts to prevent host initialisation
            1.2.2.2 Exhausting host resources with fake DAD messages
            
    1.3 Man-in-the-middle (MitM) & interception [OR]
    
        1.3.1 Traffic redirection
            1.3.1.1 Intercepting and modifying IPv6 traffic
            1.3.1.2 SSL/TLS stripping for unencrypted data capture
            
        1.3.2 Software update hijacking
            1.3.2.1 Redirecting update requests to malicious servers
            1.3.2.2 Distributing trojanised updates (e.g., TheWizards' Spellbinder tool) 
            
    1.4 Evasion & stealth techniques [OR]
    
        1.4.1 Extension header abuse
            1.4.1.1 Concealing RA messages in Hop-by-Hop or Destination Options headers
            1.4.1.2 Bypassing RA guard protections 
            
        1.4.2 Low-rate attacks
            1.4.2.1 Sparse RA injections to avoid detection
            1.4.2.2 Timing-based evasion of monitoring systems
            
    1.5 Lateral movement & persistence [OR]
    
        1.5.1 Network reconnaissance
            1.5.1.1 Mapping IPv6 topology via rogue RAs
            1.5.1.2 Identifying high-value targets for further exploitation
            
        1.5.2 Persistent backdoors
            1.5.2.1 Maintaining access via malicious default gateways
            1.5.2.2 Re-infecting hosts after network resets
            
    1.6 IoT & embedded device targeting [OR]
    
        1.6.1 Resource-constrained exploitation
            1.6.1.1 Overloading IoT devices with fraudulent RAs
            1.6.1.2 Disrupting critical infrastructure (e.g., ICS/SCADA) 
            
        1.6.2 Default configuration abuse
            1.6.2.1 Exploiting weak or absent IPv6 security on IoT devices
            1.6.2.2 Enabling botnet recruitment via SLAAC
            
    1.7 Cloud & virtualisation attacks [OR]
    
        1.7.1 Virtual network exploitation
            1.7.1.1 Spoofing RAs in cloud environments (e.g., AWS VPC, Azure)
            1.7.1.2 Bypassing cloud security groups via IPv6
            
        1.7.2 Container network attacks
            1.7.2.1 Targeting Kubernetes CNI plugins with malicious RAs
            1.7.2.2 Compromising container isolation through IPv6
            
    1.8 IPv4-IPv6 transition attacks [OR]
    
        1.8.1 NAT-PT exploitation
            1.8.1.1 Abusing transition mechanisms to redirect IPv4 traffic over IPv6
            1.8.1.2 DNS ALG manipulation for address translation bypass 
            
        1.8.2 Dual-stack abuse
            1.8.2.1 Forcing IPv6 preference over IPv4 for attack enablement
            1.8.2.2 Evading IPv4-focused security controls
            
    1.9 Application-specific attacks [OR]
    
        1.9.1 DNS hijacking
            1.9.1.1 Poisoning DNS via RDNSS spoofing
            1.9.1.2 Targeting specific domains (e.g., software update servers) 
            
        1.9.2 VoIP & video conferencing exploitation
            1.9.2.1 Intercepting real-time communications
            1.9.2.2 Redirecting media streams to attacker endpoints
            
    1.10 Advanced persistent threat (APT) techniques [OR]
    
        1.10.1 Long-term espionage
            1.10.1.1 Sustained traffic interception for data exfiltration
            1.10.1.2 Targeting specific sectors (e.g., gambling, telecommunications) 
            
        1.10.2 Tool customisation
            1.10.2.1 Developing bespoke tools (e.g., Spellbinder) for SLAAC exploitation 
            1.10.2.2 Adapting attacks to evade signature-based detection
```

## Why it works

-   Lack of authentication: RA messages are unauthenticated by default, allowing any device on the local link to advertise itself as a router
-   Protocol trust model: IPv6 assumes a trusted network environment, making it susceptible to insider threats and lateral movement
-   Default enablement: Most modern OSes enable IPv6 and prioritise it over IPv4, ensuring attacks work even in dual-stack environments
-   Limited monitoring: Many organisations neglect IPv6 traffic monitoring, allowing attacks to go undetected
-   Complexity: IPv6's increased complexity (e.g., extension headers) creates blind spots in security tools
