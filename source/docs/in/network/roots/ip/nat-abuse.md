# NAT abuse (IPv4)

## Attack pattern

Network Address Translation (NAT) is a method used to map private IP addresses to a public IP address, enabling multiple devices to share a single public IP. While NAT provides address conservation and a layer of obscurity, it introduces unique attack vectors and can be exploited to bypass security controls.

```text
1. NAT Abuse [OR]

    1.1 NAT Transversal Attacks [OR]
    
        1.1.1 TCP Hole Punching
            1.1.1.1 Simultaneous SYN Packet Techniques
            1.1.1.2 Port Prediction Algorithms
            1.1.1.3 Protocol-Specific Helpers (e.g., FTP)
            
        1.1.2 UDP Hole Punching
            1.1.2.1 STUN-Based Transversal
            1.1.2.2 TURN Relay Exploitation
            1.1.2.3 ICE Protocol Manipulation
            
        1.1.3 ICMP Transversal
            1.1.3.1 ICMP Error Message Abuse
            1.1.3.2 Ping Tunnel Establishment
            1.1.3.3 Covert ICMP Channels
            
    1.2 State Table Exhaustion [OR]
    
        1.2.1 Connection Flooding
            1.2.1.1 SYN Flood to Exhaust NAT Table
            1.2.1.2 UDP Session Flooding
            1.2.1.3 ICMP Flood to Consume State Resources
            
        1.2.2 Persistent Connection Attacks
            1.2.2.1 Long-Lived TCP Connections
            1.2.2.2 UDP Stream Maintenance
            1.2.2.3 NAT Keep-Alive Exploitation
            
    1.3 Application Layer Gateway (ALG) Exploits [OR]
    
        1.3.1 ALG Bypass Techniques
            1.3.1.1 Protocol Violation Attacks
            1.3.1.2 Encrypted Payload Bypass
            1.3.1.3 ALG Resource Exhaustion
            
        1.3.2 ALG-Specific Vulnerabilities
            1.3.2.1 SIP ALG Buffer Overflows
            1.3.2.2 FTP ALG Security Bypass
            1.3.2.3 DNS ALG Cache Poisoning
            
    1.4 Port Forwarding Abuse [OR]
    
        1.4.1 Unauthorised Access Through Forwarding
            1.4.1.1 Default Password Access to Forwarded Services
            1.4.1.2 Service Enumeration Through Forwarded Ports
            1.4.1.3 Backdoor Installation via Forwarded Services
            
        1.4.2 DMZ Host Exploitation
            1.4.2.1 DMZ Host as Attack Launch Point
            1.4.2.2 DMZ to Internal Network Pivoting
            1.4.2.3 DMZ Host Compromise
            
    1.5 NAT Slipstreaming [OR]
    
        1.5.1 Protocol Impersonation
            1.5.1.1 HTTP Header Manipulation
            1.5.1.2 SIP Message Injection
            1.5.1.3 FTP PORT Command Abuse
            
        1.5.2 Browser-Based Attacks
            1.5.2.1 WebRTC NAT Bypass
            1.5.2.2 JavaScript NAT Slipstreaming
            1.5.2.3 Cross-Protocol Attacks
            
    1.6 VPN Bypass Through NAT [OR]
    
        1.6.1 Split Tunnelling Exploitation
            1.6.1.1 Direct Internet Access While VPN Connected
            1.6.1.2 VPN Bypass for Malware C2
            1.6.1.3 Data Exfiltration Outside VPN Tunnel
            
        1.6.2 NAT on VPN Tunnel
            1.6.2.1 Double NAT Configuration Issues
            1.6.2.2 VPN Client NAT Bypass
            1.6.2.3 Mobile Device VPN NAT Issues
            
    1.7 Carrier-Grade NAT (CGNAT) Exploits [OR]
    
        1.7.1 Port Allocation Attacks
            1.7.1.1 Port Exhaustion at Carrier Level
            1.7.1.2 CGNAT State Table Overflow
            1.7.1.3 Shared Port Space Attacks
            
        1.7.2 User Identification Bypass
            1.7.2.1 IP Sharing for Anonymity
            1.7.2.2 CGNAT Log Evasion
            1.7.2.3 Law Enforcement Identification Challenges
            
    1.8 IoT NAT Vulnerabilities [OR]
    
        1.8.1 UPnP Exploitation
            1.8.1.1 Automatic Port Forwarding Abuse
            1.8.1.2 UPnP Reflection Attacks
            1.8.1.3 IoT Device Takeover via UPnP
            
        1.8.2 Limited NAT Traversal Capabilities
            1.8.2.1 IoT Device Isolation Bypass
            1.8.2.2 Cloud Service Impersonation
            1.8.2.3 Manufacturer Backdoor Exploitation
            
    1.9 IPv6 Transition Mechanisms [OR]
    
        1.9.1 NAT64/DNS64 Exploitation
            1.9.1.1 IPv6 to IPv4 Translation Bypass
            1.9.1.2 DNS64 Poisoning Attacks
            1.9.1.3 Protocol-Specific Translation Issues
            
        1.9.2 Dual-Stack Abuse
            1.9.2.1 IPv6 Preference Attacks
            1.9.2.2 Protocol Selection Manipulation
            1.9.2.3 Dual-Stack Implementation Flaws
```

## Why it works

-   Stateful Complexity: NAT devices maintain state tables mapping internal and external sessions. That statefulness creates a resource that can be exhausted or manipulated.
-   Protocol Helpers: Application Layer Gateways (ALGs) are designed to assist with protocol-specific transformations but often contain vulnerabilities or can be tricked.
-   Consumer Device Weaknesses: Many SOHO routers have weak default configurations, enabled UPnP by default, and rarely receive firmware updates.
-   Asymmetric Paths: NAT behaviour can be unpredictable when packets take asymmetric routes, bypassing the NAT device.
-   Address Conservation: The very purpose of NAT, sharing addresses, makes attribution difficult and enables abuse.
