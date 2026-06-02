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

## Counter moves

IoT/OT device crashes via ICMP is the case here. Filtering and rate-limiting ICMP, and watching for tunnelling, are the counters. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
