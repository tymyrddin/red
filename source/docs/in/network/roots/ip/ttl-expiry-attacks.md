# TTL expiry attacks

## Attack pattern

TTL (Time to Live) expiry attacks exploit the ICMP Time Exceeded messages generated when a packet's TTL value reaches zero. Attackers craft packets with low TTL values to force routers to generate these messages, consuming resources and potentially creating denial-of-service conditions or routing reconnaissance opportunities.

```text
1. TTL Expiry Attacks [OR]

    1.1 Resource Exhaustion Attacks [OR]
    
        1.1.1 Router CPU Exhaustion
            1.1.1.1 Flooding with packets having TTL=1
            1.1.1.2 Forcing ICMP Time Exceeded generation at line rate
            1.1.1.3 Targeting control plane processing capacity
            
        1.1.2 Bandwidth Consumption
            1.1.2.1 Generating high volumes of ICMP error messages
            1.1.2.2 Creating feedback loops with ICMP responses
            1.1.2.3 Amplification through multiple router hops
            
        1.1.3 Memory Resource Attacks
            1.1.3.1 Consuming router buffer memory with error processing
            1.1.3.2 Overflowing ICMP message queues
            1.1.3.3 Exhausting packet processing resources
            
    1.2 Network Reconnaissance [OR]
    
        1.2.1 Traceroute Exploitation
            1.2.1.1 Mapping network paths through forced TTL expiries
            1.2.1.2 Identifying all routers in a path anonymously
            1.2.1.3 Discovering network topology without permission
            
        1.2.2 Firewall and ACL Mapping
            1.2.2.1 Determining security device locations
            1.2.2.2 Identifying filtering rules through TTL expiry patterns
            1.2.2.3 Mapping security perimeters through error messages
            
        1.2.3 Load Balancer Discovery
            1.2.3.1 Identifying load balancer presence through TTL behaviour
            1.2.3.2 Mapping load balancing infrastructure
            1.2.3.3 Determining load balancer hop counts
            
    1.3 Service Disruption [OR]
    
        1.3.1 Path MTU Discovery Attacks
            1.3.1.1 Forcing Path MTU Discovery failures
            1.3.1.2 Disrupting TCP session establishment
            1.3.1.3 Causing application timeouts through MTU issues
            
        1.3.2 QoS and Policy Bypass
            1.3.2.1 Evading quality of service policies
            1.3.2.2 Bypassing traffic shaping through error messages
            1.3.2.3 Avoiding rate limiting using ICMP errors
            
        1.3.3 Routing Protocol Disruption
            1.3.3.1 Interfering with BGP session maintenance
            1.3.3.2 Disrupting OSPF or ISIS adjacencies
            1.3.3.3 Affecting routing convergence through resource exhaustion
            
    1.4 Protocol-Specific Exploitation [OR]
    
        1.4.1 TCP TTL Attacks
            1.4.1.1 SYN packets with minimal TTL to exhaust resources
            1.4.1.2 Established session TTL manipulation
            1.4.1.3 TCP session teardown through forced expiries
            
        1.4.2 UDP TTL Manipulation
            1.4.2.1 DNS query TTL attacks
            1.4.2.2 VoIP session disruption through TTL expiry
            1.4.2.3 Video streaming interruption
            
        1.4.3 ICMP-Based Attacks
            1.4.3.1 Ping flood with TTL=1
            1.4.3.2 ICMP error message amplification
            1.4.3.3 Reflection attacks using TTL expiry
            
    1.5 Evasion and Stealth Techniques [OR]
    
        1.5.1 Low-Rate Attacks
            1.5.1.1 Slow TTL expiry attacks to avoid detection
            1.5.1.2 Time-distributed TTL packets
            1.5.1.3 Below-threshold attack volumes
            
        1.5.2 Source Spoofing
            1.5.2.1 Using forged source addresses for TTL attacks
            1.5.2.2 Distributed TTL attack sources
            1.5.2.3 Botnet-based TTL expiry attacks
            
        1.5.3 Protocol Variation
            1.5.3.1 Mixing TCP, UDP, and ICMP TTL attacks
            1.5.3.2 Using different destination ports
            1.5.3.3 Varied TTL values to avoid pattern matching
            
    1.6 Application Layer Impact [OR]
    
        1.6.1 Web Service Disruption
            1.6.1.1 HTTP/HTTPS session timeouts
            1.6.1.2 API endpoint unavailability
            1.6.1.3 Content delivery network disruption
            
        1.6.2 Database Service Attacks
            1.6.2.1 SQL connection timeouts
            1.6.2.2 Database replication disruption
            1.6.2.3 Transaction processing failures
            
        1.6.3 Cloud Service Targeting
            1.6.3.1 SaaS application disruption
            1.6.3.2 PaaS infrastructure exhaustion
            1.6.3.3 IaaS resource consumption
            
    1.7 Advanced Persistent Techniques [OR]
    
        1.7.1 Multi-Vector Coordination
            1.7.1.1 Combining TTL attacks with other DDoS methods
            1.7.1.2 Layered attack strategies
            1.7.1.3 Time-synchronised multi-point attacks
            
        1.7.2 Stateful Attack Patterns
            1.7.2.1 Protocol state-aware TTL manipulation
            1.7.2.2 Session-specific TTL targeting
            1.7.2.3 Application-aware expiry attacks
            
        1.7.3 Zero-Day Exploitation
            1.7.3.1 Novel TTL handling vulnerabilities
            1.7.3.2 New protocol TTL weaknesses
            1.7.3.3 Emerging device TTL processing flaws
            
    1.8 Infrastructure-Specific Attacks [OR]
    
        1.8.1 Router-Specific Exploitation
            1.8.1.1 Vendor-specific TTL processing vulnerabilities
            1.8.1.2 ASIC-based TTL handling flaws
            1.8.1.3 Control plane protection bypass
            
        1.8.2 Switch Targeting
            1.8.2.1 Layer 3 switch TTL processing
            1.8.2.2 Multicast TTL manipulation
            1.8.2.3 VLAN hopping through TTL expiry
            
        1.8.3 Security Device Attacks
            1.8.3.1 Firewall TTL processing exhaustion
            1.8.3.2 IPS/IDS evasion through TTL manipulation
            1.8.3.3 VPN concentrator targeting
```

## Why it works

-   Protocol Requirement: Routers process TTL expiry and generate ICMP Time Exceeded messages as a function of the protocol.
-   Resource Intensive: ICMP generation consumes router CPU and memory.
-   Amplification Potential: Small packets can generate larger ICMP responses.
-   State Exhaustion: Connection tracking resources can be consumed.
-   Evasion Capabilities: TTL manipulation can bypass some security controls.

## Counter moves

TTL expiry attacks is what this page works through. Anti-spoofing filters such as BCP 38, and segmentation, close it. The defender's view is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
