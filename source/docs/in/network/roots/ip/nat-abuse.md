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
    
        1.4.1 Unauthorized Access Through Forwarding
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
    
        1.6.1 Split Tunneling Exploitation
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
            1.8.2.2 Cloud Service impersonation
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

-   Stateful Complexity: NAT devices must maintain state tables mapping internal and external sessions. This statefulness creates a resource that can be exhausted or manipulated.
-   Protocol Helpers: Application Layer Gateways (ALGs) are designed to assist with protocol-specific transformations but often contain vulnerabilities or can be tricked.
-   Consumer Device Weaknesses: Many SOHO routers have weak default configurations, enabled UPnP by default, and rarely receive firmware updates.
-   Asymmetric Paths: NAT behavior can be unpredictable when packets take asymmetric routes, bypassing the NAT device.
-   Address Conservation: The very purpose of NAT—sharing addresses—makes attribution difficult and enables abuse.

## Mitigation

### State table protection
-   Action: Harden NAT devices against state exhaustion attacks.
-   How:
    -   Timeout Tuning: Reduce state timeouts for TCP (especially half-open connections), UDP, and ICMP.
        -   Cisco ASA: `timeout conn 1:00:00 half-closed 0:10:00 udp 0:02:00 icmp 0:00:02`
    -   Connection Rate Limiting: Implement limits on new connections per second from a single internal host to prevent flooding.
        -   iptables: `iptables -A FORWARD -p tcp -m state --state NEW -m limit --limit 60/s -j ACCEPT`
    -   Maximum Connections: Enforce a maximum number of concurrent connections per host.

### Disable unnecessary ALGs
-   Action: Identify and disable Application Layer Gateways that are not strictly required.
-   How:
    -   Cisco Router: `no ip nat service alg-ftp`, `no ip nat service alg-sip`
    -   Checkpoint Firewall: Disable ALGs in the NAT policy.
    -   SOHO Routers: Access administrative interface and disable UPnP and specific ALGs if possible.
-   Benefit: Reduces the attack surface by eliminating potential protocol manipulation points.

### Secure port forwarding
-   Action: Manage port forwarding rules with a security-first mindset.
-   How:
    -   Least Privilege: Only forward ports that are absolutely necessary. Never forward ports to sensitive internal servers.
    -   Strong Authentication: Ensure any service exposed via port forwarding has strong, unique credentials and multi-factor authentication if possible.
    -   DMZ Hosts: Avoid using the DMZ feature. If used, the DMZ host should be hardened as if it were directly on the internet.

### IPv6 transition
-   Action: The ultimate mitigation for NAT complexity is to adopt IPv6.
-   How:
    -   Dual-Stack Deployment: Run IPv4 and IPv6 simultaneously.
    -   NAT64/DNS64: For IPv6-only clients to access IPv4 resources, use secure translation mechanisms instead of large-scale NAT.
    -   Benefits: Eliminates state exhaustion attacks, simplifies network architecture, and restores end-to-end connectivity.

### Network monitoring
-   Action: Actively monitor for signs of NAT abuse.
-   How:
    -   NAT Table Monitoring: Monitor the size and growth of the NAT state table. Set alerts for rapid growth or near-capacity conditions.
    -   Flow Logging: Use NetFlow, IPFIX, or vendor-specific logging to track unusual patterns, such as a single internal host creating thousands of connections.
    -   IDS/IPS: Deploy signatures to detect known NAT slipstreaming techniques and protocol attacks.

### Carrier-Grade NAT (CGNAT) specific protections
-   Action: For ISPs, implement additional protections due to the scale of CGNAT.
-   How:
    -   Port Allocation Algorithms: Use deterministic or paired port allocation to make abuse more difficult.
    -   Logging: Maintain adequate logs for forensic purposes, balancing privacy concerns.
    -   Rate Limiting: Enforce strict per-subscriber rate limits on new connections and overall throughput.
