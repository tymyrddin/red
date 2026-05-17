# Multiprotocol label switching (MPLS) attacks (MP-BGP)

## Attack pattern

Multiprotocol label switching (MPLS) is a widely deployed networking technology that uses labels instead of network addresses to route traffic optimally via shorter pathways. While MPLS offers significant benefits for traffic engineering and quality of service, it introduces unique attack vectors that can compromise network security, availability, and integrity. MPLS attacks typically target the control plane, data plane, or management interfaces of MPLS networks.

```text
1. MPLS infrastructure attacks [OR]

    1.1 Label spoofing and manipulation [OR]
    
        1.1.1 Forged label injection
            1.1.1.1 Inserting malicious labels into MPLS packets
            1.1.1.2 Label stack manipulation to redirect traffic
            1.1.1.3 Creating invalid label combinations
            
        1.1.2 Label distribution protocol exploitation
            1.1.2.1 LDP session hijacking
            1.1.2.2 Forged label mapping messages
            1.1.2.3 Label withdrawal attacks
            
    1.2 Control plane attacks [OR]
    
        1.2.1 Routing protocol targeting
            1.2.1.1 BGP/MPLS IP VPN route distribution attacks
            1.2.1.2 Route target manipulation
            1.2.1.3 Route distinguisher spoofing
            
        1.2.2 RSVP-TE exploitation
            1.2.2.1 Reservation request spoofing
            1.2.2.2 Path message manipulation
            1.2.2.3 Bandwidth reservation exhaustion
            
    1.3 Data plane attacks [OR]
    
        1.3.1 Label switched path hijacking
            1.3.1.1 Unauthorised LSP creation
            1.3.1.2 LSP rerouting attacks
            1.3.1.3 Traffic interception via LSP manipulation
            
        1.3.2 MPLS tunnelling exploitation
            1.3.2.1 Tunnel header manipulation
            1.3.2.2 Label stack depth attacks
            1.3.2.3 Time-to-live field exploitation
            
    1.4 VPN targeting [OR]
    
        1.4.1 MPLS VPN attacks
            1.4.1.1 VPN route injection
            1.4.1.2 Route leakage between VPNs
            1.4.1.3 VPN isolation bypass
            
        1.4.2 Layer 2 VPN exploitation
            1.4.2.1 VPLS MAC address spoofing
            1.4.2.2 Pseudowire manipulation
            1.4.2.3 Ethernet over MPLS attacks
            
    1.5 Management plane attacks [OR]
    
        1.5.1 MPLS MIB exploitation
            1.5.1.1 SNMP-based configuration manipulation
            1.5.1.2 Tunnel parameter modification
            1.5.1.3 Performance data manipulation
            
        1.5.2 Traffic engineering database attacks
            1.5.2.1 TED manipulation for path calculation
            1.5.2.2 Resource availability falsification
            1.5.2.3 Constraint-based routing exploitation
            
    1.6 QoS and traffic class exploitation [OR]
    
        1.6.1 Quality of service manipulation
            1.6.1.1 EXP field modification for priority manipulation
            1.6.1.2 Bandwidth reservation attacks
            1.6.1.3 Traffic class reassignment
            
        1.6.2 Traffic engineering bypass
            1.6.2.1 Constraint avoidance attacks
            1.6.2.2 Affinity attribute manipulation
            1.6.2.3 Administrative weight modification
            
    1.7 Inter-provider attacks [OR]
    
        1.7.1 AS boundary exploitation
            1.7.1.1 Inter-AS VPN manipulation
            1.7.1.2 Route target filtering bypass
            1.7.1.3 Multi-provider trust exploitation
            
        1.7.2 Carrier's carrier attacks
            1.7.2.1 Hierarchical VPN exploitation
            1.7.2.2 Label distribution between providers
            1.7.2.3 Backbone service manipulation
            
    1.8 Denial of service attacks [OR]
    
        1.8.1 Resource exhaustion
            1.8.1.1 Label space exhaustion
            1.8.1.2 LSP state table overflow
            1.8.1.3 Control plane saturation
            
        1.8.2 Path disruption
            1.8.2.1 LSP tearing attacks
            1.8.2.2 Fast reroute exploitation
            1.8.2.3 Make-before-break manipulation
            
    1.9 Advanced persistent threats [OR]
    
        1.9.1 Stealthy label manipulation
            1.9.1.1 Low-rate label spoofing
            1.9.1.2 Time-based attack synchronisation
            1.9.1.3 Detection evasion techniques
            
        1.9.2 Multi-vector MPLS attacks
            1.9.2.1 Combined control and data plane attacks
            1.9.2.2 Cross-protocol exploitation
            1.9.2.3 Coordinated multi-point attacks
            
    1.10 Legacy integration attacks [OR]
    
        1.10.1 ATM-MPLS integration exploitation
            1.10.1.1 ATM virtual circuit to MPLS label manipulation
            1.10.1.2 Interworking function attacks
            1.10.1.3 Cell-to-packet translation vulnerabilities
            
        1.10.2 Frame relay MPLS exploitation
            1.10.2.1 DLCI to label mapping attacks
            1.10.2.2 FRF.16 implementation vulnerabilities
            1.10.2.3 Legacy protocol tunnelling attacks
```

## Why it works

-   Protocol complexity: MPLS integrates multiple networking technologies (Layer 2 and Layer 3), creating a large attack surface.
-   Trust-based operations: MPLS relies on trust relationships between routers and switches, particularly in label distribution.
-   Limited authentication: Many MPLS control protocols lack strong authentication mechanisms by default.
-   Visibility challenges: MPLS traffic is often not deeply inspected by security devices due to label-based forwarding.
-   Inter-provider dependencies: Multi-provider MPLS implementations create complex trust relationships that can be exploited.
-   Legacy integration: Support for legacy technologies (ATM, Frame Relay) introduces historical vulnerabilities.
