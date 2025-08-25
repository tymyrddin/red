# Internet Protocol version 6 (IPv6) protocol notes

## 1. Advantages of IPv6 Deployment

- Vast Address Space: 128-bit addresses (≈3.4×10³⁸ addresses) eliminate scarcity.
- Simplified Header: Streamlined base header improves router processing efficiency.
- Stateless Address Autoconfiguration (SLAAC): Hosts can self-configure addresses without DHCP.
- Built-in Security: IPsec (authentication/encryption) is mandatory, enhancing end-to-end security.
- Improved Multicast & Anycast: Efficient group communication and service delivery.
- No NAT Required: Restores end-to-end connectivity, simplifying applications.
- Better Mobility Support: Mobile IPv6 handles roaming more effectively.

## 2. Writing IPv6 Addresses (Best Practices)

- Compression: Remove leading zeros in each hextet (16-bit block) and replace the longest consecutive sequence of all-zero hextets with `::` (once per address).
  - Example: `2001:0db8:0000:130f:0000:0000:08ec:140b` → `2001:db8:0:130f::8ec:140b`
- Lowercase: Use lowercase letters (e.g., `fd00::1`, not `FD00::1`).
- CIDR Notation: Always include prefix length (e.g., `2001:db8::/32`).

## 3. IPv6 Address Types & Scopes

| Type               | Prefix        | Scope                     | Use Case                          |
|------------------------|-------------------|-------------------------------|---------------------------------------|
| Global Unicast     | `2000::/3`        | Global (internet)             | Public addresses, routable worldwide. |
| Unique Local (ULA) | `fd00::/8`        | Site-local (private)          | Internal networks (not routable online). |
| Link-Local         | `fe80::/10`       | Link-local (same subnet)      | Neighbor Discovery, SLAAC.            |
| Multicast          | `ff00::/8`        | Varies (e.g., `ff02::` = link) | Group communication (e.g., `ff02::1` = all nodes). |
| Loopback           | `::1/128`         | Node-local                    | Localhost.                            |
| Unspecified        | `::/128`          | None                          | Absence of address (e.g., DAD).       |

## 4. Calculating IPv6 Subnets

- Subnetting borrows bits from the host portion to create subnets.
- Formula: Number of subnets = `2^(new_prefix - current_prefix)`
- Example: How many `/64` subnets in a `/56`?  
  `2^(64-56) = 2^8 = 256` subnets.
- Subnet ranges:  
  - Base: `2001:db8:abc::/56`  
  - Subnet 1: `2001:db8:abc:0::/64`  
  - Subnet 2: `2001:db8:abc:1::/64`  
  - ...  
  - Subnet 256: `2001:db8:abc:ff::/64`

## 5. Key IPv6-Related Protocols

- NDP (Neighbor Discovery Protocol): Replaces ARP, manages neighbor reachability.
- SLAAC (Stateless Address Autoconfiguration): Hosts generate addresses using RA messages.
- DHCPv6: Stateful address/config assignment (complements SLAAC).
- ICMPv6: Error reporting and diagnostic functions (e.g., `ping6`).
- PMTUD (Path MTU Discovery): Determines optimal packet size for a path.

## 6. Characteristics & Security Concerns

- Characteristics:  
  - No broadcast (uses multicast).  
  - Extension headers for optional features.  
  - Simplified fragmentation (handled by source).  
- Security Concerns:  
  - RA Guard: Needed to block rogue Router Advertisements.  
  - DHCPv6 Spoofing: Attackers may impersonate DHCPv6 servers.  
  - Extension Header Attacks: Can be used to evade firewalls.  
  - Privacy Extensions: Temporary addresses mitigate tracking.  
  - Address Scanning Harder: Large address space makes reconnaissance difficult.

## 7. Creating an IPv6 Addressing Plan

1. Get Allocation: Obtain a prefix from ISP/RIR (e.g., `/48` for a site).
2. Hierarchical Design:  
   - Reserve bits for hierarchy (e.g., region, site, subnet).  
   - Example: `/48` → `/52` per region → `/56` per site → `/64` per LAN.
3. Subnet Allocation:  
   - Assign `/64` per VLAN/segment (required for SLAAC).  
   - Reserve blocks for future growth (e.g., IoT, guests).
4. Documentation: Record assignments in a subnetting table.

## 8. IPv6 Transition Mechanisms

- Dual Stack: Run IPv4 and IPv6 simultaneously on devices.
- Tunneling: Encapsulate IPv6 in IPv4 (e.g., 6in4, GRE).
- Translation: Convert between v4 and v6 (e.g., NAT64, SIIT).
- Proxying: Use a proxy for protocol translation.
- 464XLAT: Allows IPv4-only apps to work in an IPv6 network (common in mobile networks).

## Quick Reference

- /48: Typical assignment for a site.
- /56: Typical for residential/large subnet allocation.
- /64: Standard subnet size (one LAN).
- Link-Local: Essential for NDP and SLAAC—always present on interfaces.

Use this cheat sheet for exams, planning, and troubleshooting!