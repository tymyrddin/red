# MP-BGP session attacks

## Attack pattern

Multiprotocol Border Gateway Protocol (MP-BGP) extends traditional BGP to support multiple network layer protocols, including IPv6, VPNs, and multicast routing. While MP-BGP enables critical functionality for modern networks, it introduces additional attack vectors that target session establishment, path attributes, and protocol-specific extensions. MP-BGP session attacks exploit vulnerabilities in the implementation and configuration of multiprotocol capabilities to disrupt routing, intercept traffic, or compromise network infrastructure.

```text
1. MP-BGP session attacks [OR]

    1.1 Session establishment exploitation [OR]
    
        1.1.1 Multiprotocol capability negotiation attacks
            1.1.1.1 Capability advertisement manipulation
            1.1.1.2 Forced capability downgrade attacks
            1.1.1.3 Unsupported address family exploitation
            
        1.1.2 TCP session manipulation
            1.1.2.1 MP-BGP session hijacking
            1.1.2.2 TCP sequence number prediction
            1.1.2.3 Session reset attacks
            
        1.1.3 Authentication bypass
            1.1.3.1 MD5 hash collision attacks
            1.1.3.2 TCP-AO implementation vulnerabilities
            1.1.3.3 Key management exploitation
            
    1.2 Address family exploitation [OR]
    
        1.2.1 IPv6 address family attacks
            1.2.1.1 IPv6 NLRI manipulation
            1.2.1.2 IPv6 next-hop attribute spoofing
            1.2.1.3 Dual-stack session exploitation
            
        1.2.2 VPN address family targeting
            1.2.2.1 Route target contamination
            1.2.2.2 VPNv4 route distribution attacks
            1.2.2.3 Route distinguisher manipulation
            
        1.2.3 Multicast address family attacks
            1.2.3.1 Multicast NLRI spoofing
            1.2.3.2 RPF check bypass techniques
            1.2.3.3 Multicast tree manipulation
            
    1.3 Path attribute manipulation [OR]
    
        1.3.1 Extended community exploitation
            1.3.1.1 Route target community forging
            1.3.1.2 SoO (Site of Origin) manipulation
            1.3.1.3 Color community exploitation
            
        1.3.2 MP_REACH_NLRI attribute attacks
            1.3.2.1 Next-hop attribute spoofing
            1.3.2.2 AFI/SAFI field manipulation
            1.3.2.3 NLRI length field exploitation
            
        1.3.3 MP_UNREACH_NLRI attribute attacks
            1.3.3.1 Route withdrawal attacks
            1.3.3.2 Selective route suppression
            1.3.3.3 Route flap damping exploitation
            
    1.4 Control plane saturation attacks [OR]
    
        1.4.1 Update message flooding
            1.4.1.1 MP-BGP update storm attacks
            1.4.1.2 Path attribute flooding
            1.4.1.3 Withdrawal message flooding
            
        1.4.2 Resource exhaustion attacks
            1.4.2.1 RIB memory exhaustion
            1.4.2.2 Session buffer overflow
            1.4.2.3 CPU exhaustion through complex NLRI processing
            
        1.4.3 Keepalive exploitation
            1.4.3.1 Keepalive timer manipulation
            1.4.3.2 Hold timer exhaustion attacks
            1.4.3.3 Notification message exploitation
            
    1.5 Convergence manipulation [OR]
    
        1.5.1 Path selection attacks
            1.5.1.1 LOCAL_PREF manipulation
            1.5.1.2 MED attribute spoofing
            1.5.1.3 AS_PATH prepending attacks
            
        1.5.2 Route reflection exploitation
            1.5.2.1 Rogue route reflector attacks
            1.5.2.2 Cluster list manipulation
            1.5.2.3 Originator ID spoofing
            
        1.5.3 Confederations exploitation
            1.5.3.1 Sub-AS manipulation
            1.5.3.2 Confederation segment spoofing
            1.5.3.3 Intra-confederation attacks
            
    1.6 Security mechanism bypass [OR]
    
        1.6.1 RPKI exploitation
            1.6.1.1 ROA validation bypass
            1.6.1.2 RPKI cache poisoning
            1.6.1.3 Ghostbusters record exploitation
            
        1.6.2 BGPsec attacks
            1.6.2.1 Signature validation bypass
            1.6.2.2 Algorithm downgrade attacks
            1.6.2.3 Path validation exploitation
            
        1.6.3 GTSM bypass techniques
            1.6.3.1 TTL manipulation attacks
            1.6.3.2 Directly connected session exploitation
            1.6.3.3 Multi-hop session attacks
            
    1.7 Implementation-specific attacks [OR]
    
        1.7.1 Vendor-specific vulnerabilities
            1.7.1.1 Cisco IOS XR MP-BGP exploits
            1.7.1.2 Juniper Junos MP-BGP vulnerabilities
            1.7.1.3 Nokia SR OS implementation flaws
            
        1.7.2 Software version exploitation
            1.7.2.1 Known vulnerability exploitation
            1.7.2.2 Zero-day MP-BGP vulnerabilities
            1.7.2.3 Patch gap exploitation
            
        1.7.3 Hardware-specific attacks
            1.7.3.1 Route processor targeting
            1.7.3.2 Line card exploitation
            1.7.3.3 Memory architecture attacks
            
    1.8 Monitoring evasion [OR]
    
        1.8.1 Stealthy route manipulation
            1.8.1.1 Low-rate update attacks
            1.8.1.2 Timing-based evasion
            1.8.1.3 Legitimate-looking update crafting
            
        1.8.2 Log manipulation
            1.8.2.1 Syslog evasion techniques
            1.8.2.2 NetFlow data manipulation
            1.8.2.3 BGP monitoring protocol exploitation
            
        1.8.3 Forensic obfuscation
            1.8.3.1 AS path hiding techniques
            1.8.3.2 Community attribute obfuscation
            1.8.3.3 Timestamp manipulation
            
    1.9 Cross-protocol attacks [OR]
    
        1.9.1 IGP-BGP interaction exploitation
            1.9.1.1 Route redistribution attacks
            1.9.1.2 Backdoor route injection
            1.9.1.3 IGP metric manipulation
            
        1.9.2 MPLS-BGP integration attacks
            1.9.2.1 Label spoofing through MP-BGP
            1.9.2.2 VPN label manipulation
            1.9.2.3 Layer 3 VPN exploitation 
            
        1.9.3 DNS-BGP interaction attacks
            1.9.3.1 DNS-based BGP manipulation
            1.9.3.2 Reverse path verification bypass
            1.9.3.3 Anycast session exploitation
            
    1.10 Advanced persistent threats [OR]
    
        1.10.1 State-sponsored attacks
            1.10.1.1 Nation-state MP-BGP exploitation
            1.10.1.2 Critical infrastructure targeting
            1.10.1.3 Long-term route manipulation
            
        1.10.2 Organised crime targeting
            1.10.2.1 Financial institution targeting
            1.10.2.2 Cryptocurrency exchange attacks 
            1.10.2.3 Ransomware infrastructure attacks
            
        1.10.3 Insider threat exploitation
            1.10.3.1 Rogue administrator attacks
            1.10.3.2 Compromised credential exploitation
            1.10.3.3 Configuration manipulation
```

## Why it works

-   **Protocol complexity**: MP-BGP's extension mechanisms and multiple address families create a large attack surface with numerous implementation inconsistencies 
-   **Trust-based operations**: MP-BGP inherits BGP's trust model, assuming peers are authentic and announcements are valid 
-   **Limited validation**: Many implementations lack comprehensive validation of MP-BGP attributes and extensions
-   **Vendor inconsistencies**: Different vendors implement MP-BGP features differently, leading to security gaps
-   **Monitoring challenges**: MP-BGP's additional attributes make monitoring and detection more complex than standard BGP
-   **Skill gap**: Many network engineers have limited experience with MP-BGP's advanced features, leading to misconfigurations

## Mitigation

### Session security hardening
-   **Action**: Implement strong session protection for all MP-BGP sessions
-   **How**:
    -   Enable TCP-AO (Authentication Option) for all sessions 
    -   Implement GTSM (Generalised TTL Security Mechanism) to prevent remote session attacks
    -   Use unique passwords for each session and rotate regularly
-   **Configuration example (Cisco)**:

```text
router bgp 65001
 neighbor 2001:db8::1 remote-as 65002
 neighbor 2001:db8::1 password STRONG_PASSWORD
 neighbor 2001:db8::1 ttl-security hops 1
```

### Address family validation
-   **Action**: Validate and filter address family announcements
-   **How**:
    -   Implement strict AFI/SAFI filtering based on peer relationships
    -   Use route policies to validate NLRI formats for each address family
    -   Monitor for unexpected address family advertisements
-   **Best practice**: Regular audit of address family policies and filters

### Path attribute validation
-   **Action**: Implement comprehensive path attribute validation
-   **How**:
    -   Validate EXTENDED_COMMUNITIES and other MP-BGP attributes
    -   Implement maximum prefix limits per address family
    -   Use route policies to detect anomalous attribute combinations
-   **Configuration example (Junos)**:

```text
policy-statement mp-bgp-validation {
    term validate-afi {
        from family inet-vpn;
        then validation-state valid;
    }
    term reject-invalid {
        then reject;
    }
}
```

### Control plane protection
-   **Action**: Protect the control plane from MP-BGP specific attacks
-   **How**:
    -   Implement control plane policing with MP-BGP awareness
    -   Use queueing policies to prioritize critical MP-BGP updates
    -   Implement rate limiting for update messages per address family
-   **Tools**: Use vendor-specific control plane protection mechanisms

### Monitoring and detection
-   **Action**: Implement MP-BGP specific monitoring and detection
-   **How**:
    -   Monitor MP-BGP session statistics and update rates
    -   Implement anomaly detection for address family changes
    -   Use BGP monitoring tools with MP-BGP support
-   **Best practice**: Regular review of MP-BGP monitoring alerts

### RPKI and BGPsec implementation
-   **Action**: Deploy routing security infrastructure for MP-BGP
-   **How**:
    -   Implement RPKI for origin validation of all address families
    -   Deploy BGPsec where supported for path validation
    -   Use ROV (Route Origin Validation) for IPv6 and VPN address families 
-   **Configuration example**:

```text
rpki server
 host 203.0.113.1 port 323
address-family ipv6
 rpki origin-as validation
```

### Regular security assessment
-   **Action**: Conduct regular MP-BGP security assessments
-   **How**:
    -   Perform penetration testing of MP-BGP implementations
    -   Conduct configuration audits for all MP-BGP speakers
    -   Test failover and convergence under attack scenarios
-   **Tools**: Use MP-BGP specific testing tools and frameworks

### Vendor coordination
-   **Action**: Work with vendors on MP-BGP security issues
-   **How**:
    -   Subscribe to vendor security advisories for MP-BGP vulnerabilities
    -   Participate in vendor security programmes
    -   Report discovered vulnerabilities responsibly
-   **Best practice**: Maintain relationships with vendor security teams

## Key insights from real-world implementations

-   **Protocol complexity**: MP-BGP's extension mechanisms significantly increase the attack surface compared to standard BGP 
-   **Validation gaps**: Many implementations lack comprehensive validation of MP-BGP specific attributes
-   **Monitoring challenges**: Traditional BGP monitoring tools often lack MP-BGP awareness
-   **Vendor inconsistencies**: Different vendors implement MP-BGP features differently, creating security gaps

## Future trends and recommendations

-   **Automated validation**: Development of machine learning-based MP-BGP anomaly detection
-   **Standardised security**: Industry-wide standards for MP-BGP security implementation
-   **Protocol simplification**: Efforts to simplify MP-BGP without reducing functionality
-   **Enhanced monitoring**: Next-generation monitoring tools with MP-BGP awareness

## Conclusion

MP-BGP session attacks represent a significant threat to modern networks that rely on multiprotocol routing capabilities. These attacks exploit the increased complexity and extended functionality of MP-BGP to disrupt routing, intercept traffic, or compromise network infrastructure. Comprehensive mitigation requires session security hardening, address family validation, path attribute validation, and specialised monitoring. As networks continue to adopt MP-BGP for advanced functionalities, maintaining robust security practices specific to MP-BGP's extended capabilities is essential for protecting network infrastructure.
