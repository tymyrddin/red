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

-   Protocol complexity: MP-BGP's extension mechanisms and multiple address families create a large attack surface with numerous implementation inconsistencies 
-   Trust-based operations: MP-BGP inherits BGP's trust model, assuming peers are authentic and announcements are valid 
-   Limited validation: Many implementations lack comprehensive validation of MP-BGP attributes and extensions
-   Vendor inconsistencies: Different vendors implement MP-BGP features differently, leading to security gaps
-   Monitoring challenges: MP-BGP's additional attributes make monitoring and detection more complex than standard BGP
-   Skill gap: Many network engineers have limited experience with MP-BGP's advanced features, leading to misconfigurations

## Counter moves

MP-BGP session attacks is the variant in play. RPKI origin validation and route monitoring are the levers. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
