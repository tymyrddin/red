# IoT/OT device crashes via ICMP

## Attack pattern

ICMP-based attacks against Internet of Things (IoT) and Operational Technology (OT) devices represent a critical threat vector that exploits the constrained resources, outdated firmware, and specialised protocol implementations found in embedded systems. These attacks leverage malformed packets, resource exhaustion techniques, and protocol stack vulnerabilities to cause device crashes, service disruption, and potentially physical system damage in industrial environments.

```text
1. IoT/OT device crashes [AND]

    1.1 Protocol stack exploitation [OR]
    
        1.1.1 Malformed ICMPv6 to embedded devices
            1.1.1.1 Invalid extension header combinations
            1.1.1.2 Corrupted option field processing
            1.1.1.3 Oversized packet handling vulnerabilities
            1.1.1.4 Fragment reassembly buffer overflows
            
        1.1.2 Resource exhaustion through ICMP
            1.1.2.1 Memory exhaustion via packet flooding
            1.1.2.2 Processor overload through complex packet processing
            1.1.2.3 Network stack resource depletion
            1.1.2.4 Connection table exhaustion through session attacks
            
        1.1.3 Firmware bug triggers
            1.1.3.1 CVE-2020-10148 and similar ICMPv6 vulnerabilities
            1.1.3.2 Buffer overflow in lightweight TCP/IP stacks
            1.1.3.3 Integer overflow in packet processing code
            1.1.3.4 Memory corruption through crafted option fields
            
    1.2 Industrial system targeting [OR]
    
        1.2.1 SCADA system ICMP vulnerabilities
            1.2.1.1 Industrial protocol stack implementation flaws
            1.2.1.2 Real-time operating system vulnerabilities
            1.2.1.3 Control system service disruption
            1.2.1.4 Human-machine interface targeting
            
        1.2.2 PLC ICMP stack corruption
            1.2.2.1 Programmable logic controller memory corruption
            1.2.2.2 Ladder logic execution disruption
            1.2.2.3 I/O module communication interference
            1.2.2.4 Safety system compromise through device crashes
            
        1.2.3 OT network protocol attacks
            1.2.3.1 Industrial protocol tunnelling over ICMP
            1.2.3.2 Fieldbus protocol disruption
            1.2.3.3 Process control system manipulation
            1.2.3.4 Safety instrumented system targeting
            
    1.3 Supply chain vulnerabilities [OR]
    
        1.3.1 Vendor-specific ICMP implementations
            1.3.1.1 Custom TCP/IP stack vulnerabilities
            1.3.1.2 Proprietary protocol handling flaws
            1.3.1.3 Hardware-specific acceleration vulnerabilities
            1.3.1.4 Reference design implementation errors
            
        1.3.2 Custom protocol stack exploits
            1.3.2.1 Lightweight stack implementation flaws
            1.3.2.2 Resource-constrained device memory issues
            1.3.2.3 Real-time operating system network stack bugs
            1.3.2.4 Embedded system compiler introduced vulnerabilities
            
        1.3.3 Legacy system compatibility attacks
            1.3.3.1 Backward compatibility mechanism exploitation
            1.3.3.2 Unmaintained firmware vulnerability targeting
            1.3.3.3 End-of-life device exploitation
            1.3.3.4 Protocol version transition attacks
            
    1.4 Hardware-specific attacks [OR]
    
        1.4.1 Microcontroller vulnerabilities
            1.4.1.1 Limited memory device targeting
            1.4.1.2 Processor exception handling exploitation
            1.4.1.3 Watchdog timer manipulation
            1.4.1.4 Peripheral device communication disruption
            
        1.4.2 Network interface targeting
            1.4.2.1 Ethernet controller firmware vulnerabilities
            1.4.2.2 Wireless module stack corruption
            1.4.2.3 Industrial network adapter exploitation
            1.4.2.4 Fieldbus interface targeting
            
    1.5 Persistence and propagation [OR]
    
        1.5.1 Device bricking attacks
            1.5.1.1 Permanent firmware corruption
            1.5.1.2 Bootloader compromise through network packets
            1.5.1.3 Configuration memory destruction
            1.5.1.4 Recovery mechanism disruption
            
        1.5.2 Worm propagation mechanisms
            1.5.2.1 Self-replicating ICMP payloads
            1.5.2.2 Network scanning through compromised devices
            1.5.2.3 Lateral movement in OT environments
            1.5.2.4 Supply chain infection propagation
            
    1.6 Physical impact attacks [OR]
    
        1.6.1 Safety system compromise
            1.6.1.1 Emergency shutdown system disruption
            1.6.1.2 Safety controller targeting
            1.6.1.3 Process safety time violation
            1.6.1.4 Protective system interference
            
        1.6.2 Process manipulation
            1.6.2.1 Industrial process disruption through device crashes
            1.6.2.2 Quality control system compromise
            1.6.2.3 Environmental control system attacks
            1.6.2.4 Energy management system targeting
```

## Why it works

-   Resource constraints: IoT/OT devices have limited memory and processing capabilities
-   Outdated firmware: Many devices run outdated software with known vulnerabilities
-   Protocol complexity: Modern ICMPv6 features overwhelm simple protocol stacks
-   Long lifecycles: Industrial devices remain in service for decades without updates
-   Network exposure: OT networks are increasingly connected to enterprise networks
-   Testing gaps: Embedded systems often lack rigorous security testing

## Mitigation

### Network segmentation

-   Action: Implement strict network segmentation for IoT/OT devices
-   How:
    -   Deploy industrial DMZs to isolate OT networks
    -   Implement network segmentation using firewalls and VLANs
    -   Use unidirectional gateways for critical control systems
    -   Implement macro and microsegmentation strategies
-   Best practice: Assume breach and segment networks to limit attack propagation

### Protocol filtering

-   Action: Implement comprehensive ICMP filtering for IoT/OT networks
-   How:
    -   Block unnecessary ICMP types at network boundaries
    -   Implement RFC-compliant ICMPv6 filtering
    -   Use deep packet inspection for industrial protocols
    -   Deploy protocol-aware firewalls for OT environments
-   Best practice: Principle of least privilege for network protocols

### Device hardening

-   Action: Harden IoT/OT devices against network attacks
-   How:
    -   Disable unnecessary network services and protocols
    -   Implement host-based firewalls where supported
    -   Use secure boot and firmware validation
    -   Regularly update device firmware and patches
-   Best practice: Regular vulnerability assessment and patch management

### Monitoring and detection

-   Action: Deploy specialised monitoring for OT environments
-   How:
    -   Implement OT-specific intrusion detection systems
    -   Monitor for abnormal ICMP traffic patterns
    -   Use network behaviour analysis for anomaly detection
    -   Deploy security information and event management for OT
-   Best practice: Continuous monitoring with OT-aware detection capabilities

### Supply chain security

-   Action: Enhance supply chain security for IoT/OT devices
-   How:
    -   Conduct security assessments before device acquisition
    -   Verify firmware integrity and digital signatures
    -   Implement secure development lifecycle requirements
    -   Establish vulnerability disclosure programmes with vendors
-   Best practice: Security-by-design principles for device procurement

## Key insights from real-world attacks

-   Critical infrastructure targeting: OT systems are increasingly targeted by sophisticated actors
-   Vulnerability persistence: Many vulnerabilities remain unpatched for years in OT environments
-   Physical consequences: Device crashes can have real-world physical impacts
-   Supply chain risks: Vulnerabilities often originate from common software components

## Future trends and recommendations

-   Increasing connectivity: More OT devices will be connected, expanding attack surfaces
-   AI-enhanced attacks: Machine learning may be used to optimise attack patterns
-   Regulatory requirements: Stricter security standards for critical infrastructure
-   Defence evolution: Specialised OT security solutions will continue to develop

## Conclusion

ICMP-based attacks against IoT and OT devices represent a severe threat to critical infrastructure and industrial systems. These attacks exploit the unique characteristics of embedded systems, including resource constraints, outdated firmware, and specialised protocol implementations. The consequences extend beyond digital disruption to potential physical damage and safety implications. Defence requires a comprehensive approach including network segmentation, protocol filtering, device hardening, specialised monitoring, and supply chain security. As IoT/OT environments become increasingly connected and critical to modern society, organisations must prioritise the security of these systems through ongoing vigilance, regular assessments, and implementation of best practices tailored to the unique requirements of operational technology environments.
