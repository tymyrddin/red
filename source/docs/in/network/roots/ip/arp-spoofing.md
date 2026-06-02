# ARP apoofing/poisoning (IPv4)

## Attack pattern

The Address Resolution Protocol (ARP) is a stateless protocol used to map IP addresses to MAC addresses on a local network segment (Layer 2). ARP spoofing (or poisoning) is a technique where an attacker sends forged ARP messages onto a LAN to manipulate the ARP caches of other devices. This allows the attacker to intercept, modify, or block network traffic.

```text
1. ARP Spoofing/Poisoning [OR]

    1.1 Man-in-the-Middle (MitM) Attacks [OR]
    
        1.1.1 Gateway Impersonation
            1.1.1.1 Spoofing the MAC address of the default gateway
            1.1.1.2 Gratuitous ARP replies announcing the attacker as gateway
            1.1.1.3 Persistent ARP cache poisoning
            
        1.1.2 Host Impersonation
            1.1.2.1 Spoofing the MAC address of specific target hosts
            1.1.2.2 ARP starvation attacks followed by impersonation
            1.1.2.3 DHCP spoofing combined with ARP poisoning
            
    1.2 Denial-of-Service (DoS) [OR]
    
        1.2.1 ARP Cache Poisoning
            1.2.1.1 Flooding with spoofed ARP replies
            1.2.1.2 Invalid MAC address assignments
            1.2.1.3 Redirecting traffic to non-existent hosts
            
        1.2.2 ARP Table Overflow
            1.2.2.1 Flooding switches with fake ARP entries
            1.2.2.2 CAM table exhaustion attacks
            1.2.2.3 Switch performance degradation
            
    1.3 Session Hijacking [OR]
    
        1.3.1 TCP Session Stealing
            1.3.1.1 Active session takeover
            1.3.1.2 Sequence number prediction
            1.3.1.3 RST injection attacks
            
        1.3.2 Application Layer Attacks
            1.3.2.1 HTTP session cookie theft
            1.3.2.2 SSL/TLS stripping attacks
            1.3.2.3 DNS spoofing through ARP poisoning
            
    1.4 VLAN Hopping [OR]
    
        1.4.1 Cross-VLAN Attacks
            1.4.1.1 Double tagging attacks
            1.4.1.2 Switch spoofing attacks
            1.4.1.3 ARP poisoning across VLAN boundaries
            
    1.5 IPv6 Neighbor Discovery Protocol (NDP) Attacks [OR]
    
        1.5.1 Neighbor Advertisement Spoofing
            1.5.1.1 IPv6 address takeover
            1.5.1.2 Router advertisement spoofing
            1.5.1.3 Redirect attacks
            
        1.5.2 Duplicate Address Detection (DAD) Attacks
            1.5.2.1 Address assignment prevention
            1.5.2.2 DoS through fake address conflicts
            
    1.6 Advanced Persistence [OR]
    
        1.6.1 Stealthy ARP Poisoning
            1.6.1.1 Low-rate poisoning attacks
            1.6.1.2 Timing-based evasion
            1.6.1.3 Selective target poisoning
            
        1.6.2 Persistent ARP Manipulation
            1.6.2.1 Scheduled ARP attacks
            1.6.2.2 Automated re-poisoning scripts
            1.6.2.3 Multi-vector ARP attacks
            
    1.7 Wireless Network Attacks [OR]
    
        1.7.1 WiFi ARP Poisoning
            1.7.1.1 Rogue access point attacks
            1.7.1.2 Evil twin attacks
            1.7.1.3 EAPOL attack combinations
            
        1.7.2 Bluetooth ARP-like Attacks
            1.7.2.1 L2CAP spoofing attacks
            1.7.2.2 BNEP manipulation attacks
            
    1.8 Industrial Control Systems (ICS) [OR]
    
        1.8.1 SCADA Network Attacks
            1.8.1.1 Modbus/TCP ARP poisoning
            1.8.1.2 PROFINET ARP manipulation
            1.8.1.3 DNP3 session hijacking
            
    1.9 Cloud and Virtual [OR]
    
        1.9.1 Hypervisor ARP Attacks
            1.9.1.1 Virtual switch ARP poisoning
            1.9.1.2 VM-to-VM ARP spoofing
            1.9.1.3 Container network ARP manipulation
            
        1.9.2 Cloud Network Attacks
            1.9.2.1 VPC ARP spoofing attacks
            1.9.2.2 Cloud load balancer poisoning
            1.9.2.3 SDN controller ARP manipulation
```

## Why it works

-   Stateless Protocol: ARP has no authentication mechanism. Devices inherently trust ARP responses without verifying their legitimacy.
-   Broadcast Nature: ARP requests are broadcast to all devices on the local network, making it easy for attackers to monitor and respond to requests.
-   Cache Updates: Most systems automatically update their ARP cache with the latest ARP response, regardless of whether they requested it (gratuitous ARP).
-   Protocol Simplicity: The simplicity of ARP makes it vulnerable to exploitation, as there are no built-in security features.
-   Layer 2 Attacks: ARP attacks occur at the data link layer, making them invisible to traditional IP-based security measures.

## Counter moves

ARP apoofing/poisoning (IPv4) is the variant in play. Anti-spoofing filters such as BCP 38, and segmentation, close it. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
