# Internet Protocol version 6 (IPv6)

## Advantages of IPv6 deployment

- Vast Address Space: 128-bit addresses (≈3.4×10³⁸ addresses) eliminate scarcity.
- Simplified Header: streamlined base header improves router processing efficiency.
- Stateless Address Autoconfiguration (SLAAC): hosts can self-configure addresses without DHCP.
- Built-in Security: IPsec (authentication/encryption) is mandatory, enhancing end-to-end security.
- Improved Multicast and Anycast: efficient group communication and service delivery.
- No NAT Required: restores end-to-end connectivity, simplifying applications.
- Better Mobility Support: Mobile IPv6 handles roaming more effectively.

## Writing IPv6 addresses

- Compression: remove leading zeros in each hextet (16-bit block) and replace the longest consecutive sequence of all-zero hextets with `::` (once per address).
  - Example: `2001:0db8:0000:130f:0000:0000:08ec:140b` → `2001:db8:0:130f::8ec:140b`
- Lowercase: use lowercase letters (e.g., `fd00::1`, not `FD00::1`).
- CIDR Notation: always include prefix length (e.g., `2001:db8::/32`).

## IPv6 address types and scopes

| Type               | Prefix      | Scope                          | Use Case                                           |
|--------------------|-------------|--------------------------------|----------------------------------------------------|
| Global Unicast     | `2000::/3`  | Global (internet)              | Public addresses, routable worldwide.              |
| Unique Local (ULA) | `fd00::/8`  | Site-local (private)           | Internal networks (not routable online).           |
| Link-Local         | `fe80::/10` | Link-local (same subnet)       | Neighbour Discovery, SLAAC.                        |
| Multicast          | `ff00::/8`  | Varies (e.g., `ff02::` = link) | Group communication (e.g., `ff02::1` = all nodes). |
| Loopback           | `::1/128`   | Node-local                     | Localhost.                                         |
| Unspecified        | `::/128`    | None                           | Absence of address (e.g., DAD).                    |

## Calculating IPv6 subnets

- Subnetting borrows bits from the host portion to create subnets.
- Formula: Number of subnets = `2^(new_prefix - current_prefix)`
- Example: how many `/64` subnets in a `/56`? `2^(64-56) = 2^8 = 256` subnets.
- Subnet ranges:
  - Base: `2001:db8:abc::/56`
  - Subnet 1: `2001:db8:abc:0::/64`
  - Subnet 2: `2001:db8:abc:1::/64`
  - Subnet 256: `2001:db8:abc:ff::/64`

## Key IPv6-related protocols

- NDP (Neighbour Discovery Protocol): replaces ARP, manages neighbour reachability.
- SLAAC (Stateless Address Autoconfiguration): hosts generate addresses using RA messages.
- DHCPv6: stateful address and config assignment (complements SLAAC).
- ICMPv6: error reporting and diagnostic functions (e.g., `ping6`).
- PMTUD (Path MTU Discovery): determines optimal packet size for a path.

## Characteristics and security concerns

- Characteristics:
  - No broadcast (uses multicast).
  - Extension headers for optional features.
  - Simplified fragmentation (handled by source).
- Security Concerns:
  - RA Guard: needed to block rogue Router Advertisements.
  - DHCPv6 Spoofing: attackers may impersonate DHCPv6 servers.
  - Extension Header Attacks: can be used to evade firewalls.
  - Privacy Extensions: temporary addresses mitigate tracking.
  - Address Scanning: large address space makes reconnaissance difficult.

## 7. IPv6 transition mechanisms

- Dual Stack: run IPv4 and IPv6 simultaneously on devices.
- Tunneling: encapsulate IPv6 in IPv4 (e.g., 6in4, GRE).
- Translation: convert between v4 and v6 (e.g., NAT64, SIIT).
- Proxying: use a proxy for protocol translation.
- 464XLAT: allows IPv4-only apps to work in an IPv6 network (common in mobile networks).

## Quick Reference

- /48: typical assignment for a site.
- /56: typical for residential or large subnet allocation.
- /64: standard subnet size (one LAN).
- Link-Local: essential for NDP and SLAAC, always present on interfaces.

## Counter moves

Internet Protocol version 6 (IPv6) is what this page works through. Segmentation, egress filtering, and flow baselining are the durable answers. The defensive counterpart is in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
