# Internet Protocol version 4 (IPv4) protocol notes

## 1. Advantages of IPv4 (Legacy Strengths)
- Universality: Supported by every network device and application globally.
- Simplicity: Mature and well-understood, with extensive troubleshooting tools.
- NAT (Network Address Translation): Conserves public addresses and adds a layer of privacy.
- Broadcast Support: Built-in mechanism for network-wide announcements.

## 2. Writing IPv4 Addresses (Best Practices)
- Dotted-Decimal Notation: Four 8-bit octets separated by dots (e.g., `192.168.1.1`).
- CIDR Notation: Always include prefix length (subnet mask) (e.g., `192.168.1.0/24`).
- Private Address Ranges:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- Avoid Leading Zeros: Write `192.168.1.1`, not `192.168.001.001`.

## 3. IPv4 Address Types & Scopes
| Type      | Range                 | Scope             | Use Case                                         |
|-----------|-----------------------|-------------------|--------------------------------------------------|
| Public    | Except private ranges | Global (internet) | Routable on the internet.                        |
| Private   | `10.0.0.0/8`          | Site-local        | Internal networks, NATed for internet.           |
|           | `172.16.0.0/12`       |                   |                                                  |
|           | `192.168.0.0/16`      |                   |                                                  |
| APIPA     | `169.254.0.0/16`      | Link-local        | Auto-configured when DHCP fails.                 |
| Loopback  | `127.0.0.0/8`         | Node-local        | Localhost (typically `127.0.0.1`).               |
| Broadcast | Subnet-specific       | Subnet-local      | Send to all hosts on the subnet.                 |
| Multicast | `224.0.0.0/4`         | Defined by TTL    | Group communication (e.g., `224.0.0.9` for RIP). |

## 4. Calculating IPv4 Subnets
- Subnetting borrows bits from the host portion to create subnets.
- Formula: Number of subnets = `2^(borrowed_bits)`
- Hosts per subnet = `2^(remaining_host_bits) - 2` (subtract network & broadcast).
- Example: Subnet `192.168.1.0/24` into four `/26` subnets:
  - Borrowed bits: `26 - 24 = 2` → `2^2 = 4` subnets.
  - Subnets: `192.168.1.0/26`, `.64/26`, `.128/26`, `.192/26`.
  - Hosts per subnet: `2^(6) - 2 = 62`.

## 5. Key IPv4-Related Protocols
- ARP (Address Resolution Protocol): Maps IP addresses to MAC addresses.
- DHCP (Dynamic Host Configuration): Assigns IP addresses and configs to hosts.
- ICMP (Internet Control Message Protocol): Error reporting and diagnostics (e.g., `ping`).
- NAT (Network Address Translation): Translates private IPs to public IPs.
- DNS (Domain Name System): Resolves domain names to IP addresses.

## 6. Characteristics & Security Concerns
- Characteristics:  
  - Uses broadcast for network-wide communication.  
  - Relies on NAT for address conservation.  
  - Header includes checksum for error detection.  
- Security Concerns:  
  - NAT Limitations: Breaks end-to-end connectivity, complicating applications like VoIP.  
  - ARP Spoofing: Attackers poison ARP tables to intercept traffic.  
  - Broadcast Storms: Misconfigurations can lead to network congestion.  
  - Address Exhaustion: Limited address space (4.3 billion addresses) has been depleted.  
  - Fragmentation Attacks: Maliciously crafted packets can evade security controls.  

## 7. Creating an IPv4 Addressing Plan
1. Determine Needs: Estimate the number of subnets and hosts per subnet.
2. Choose Private Range: Select `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`.
3. Subnet Efficiently:  
   - Use VLSM (Variable Length Subnet Masking) to avoid waste.  
   - Example: Use `/30` for point-to-point links (2 hosts), `/24` for user LANs.
4. Reserve Addresses:  
   - Reserve first/last addresses for network/broadcast.  
   - Reserve blocks for infrastructure (e.g., routers, servers).
5. Documentation: Maintain a subnetting table with assignments.

## 8. IPv4 Transition Mechanisms to IPv6
- Dual Stack: Devices run both IPv4 and IPv6 simultaneously.
- Tunneling: Encapsulate IPv6 in IPv4 packets (e.g., 6to4, Teredo).
- Translation: Convert IPv4 to IPv6 (e.g., NAT64 with DNS64).
- Proxying: Use a proxy to mediate between IPv4 and IPv6 hosts.

## Quick Reference

- /24: Common subnet mask for small networks (254 hosts).
- /30: Typical for point-to-point links (2 hosts).
- Private Ranges: Use `10.0.0.0/8` for large networks, `192.168.0.0/16` for homes.
- NAT: Essential for connecting private networks to the internet.
