# Multiprotocol BGP (MP-BGP) notes

The extensible evolution of BGP, designed to carry routing information for virtually any network layer protocol, most notably IPv6 and VPNs.

## 1. The role of MP-BGP (The "Why")

- Protocol Agnosticism: Solves the fundamental limitation of traditional BGP (IPv4-only) by enabling it to carry routing information for multiple network layer protocols.
- Address Family Support: Its primary function is to advertise routes for different Address Families (AFI) and Subsequent Address Families (SAFI), such as IPv6 Unicast, VPNv4, VPNv6, and multicast.
- Foundation for Advanced Services: The enabling technology for Layer 3 VPNs (MPLS VPNs), EVPN, and IPv6 transition mechanisms.

## 2. Key MP-BGP concepts & terminology

- Address Family Identifier (AFI): Defines the primary network layer protocol (e.g., IPv4=1, IPv6=2).
- Subsequent Address Family Identifier (SAFI): Defines the type of BGP information being carried for that protocol (e.g., Unicast=1, Multicast=2, Labeled Unicast=4, VPN=128).
- NLRI (Network Layer Reachability Information): The protocol-specific prefix being advertised (e.g., an IPv6 prefix `2001:db8::/32` or a VPNv4 prefix `RD:IPv4_prefix`).
- MP_REACH_NLRI Attribute: A new path attribute used to advertise feasible routes, including the next-hop information and the NLRI for the new address family.
- MP_UNREACH_NLRI Attribute: A new path attribute used to withdraw multiple unreachable routes for an address family efficiently.
- Route Distinguisher (RD): A 64-bit value prepended to an IPv4 or IPv6 prefix to make it unique within a BGP table (e.g., for MPLS VPNs).

## 3. MP-BGP capabilities negotiation

- BGP peers use the BGP Capabilities Advertisement mechanism (RFC 5492) during session establishment to negotiate support for specific AFI/SAFI pairs.
- A router indicates it supports MP-BGP by advertising capabilities like `AFI=2, SAFI=1` for IPv6 Unicast.
- If both peers support the same AFI/SAFI, they can exchange routes for that address family over the same single, shared TCP session used for IPv4.

## 4. Comparing classic BGP and MP-BGP

| Feature        | Classic BGP (IPv4 Unicast)             | MP-BGP                                                                           |
|:---------------|:---------------------------------------|:---------------------------------------------------------------------------------|
| NLRI Carried   | IPv4 prefixes only                     | IPv6, VPNv4, VPNv6, EVPN, etc.                                                   |
| Next-Hop Field | IPv4 address                           | Can be an IPv4 or IPv6 address, depending on the AFI/SAFI.                       |
| Session Usage  | Carries only IPv4 routes.              | Single session carries multiple address families.                                |
| Key Attributes | `NEXT_HOP` (IPv4), `ORIGIN`, `AS_PATH` | `MP_REACH_NLRI`, `MP_UNREACH_NLRI`, plus extended community attributes for VPNs. |

## 5. Common MP-BGP address families (AFI/SAFI)

| AFI/SAFI Pair         | Description                             | Use Case                              |
|:----------------------|:----------------------------------------|:--------------------------------------|
| IPv4 Unicast (1/1)    | Standard IPv4 routes.                   | The internet routing table.           |
| IPv6 Unicast (2/1)    | Standard IPv6 routes.                   | The IPv6 internet routing table.      |
| VPNv4 Unicast (1/128) | IPv4 routes with a Route Distinguisher. | MPLS L3VPNs for IPv4.                 |
| VPNv6 Unicast (2/128) | IPv6 routes with a Route Distinguisher. | MPLS L3VPNs for IPv6 (6VPE).          |
| EVPN (25/70)          | Ethernet VPN routes.                    | Layer 2 VPNs and VXLAN control plane. |
| Labeled Unicast (1/4) | IPv4 routes with an MPLS label.         | Inter-AS MPLS and Seamless MPLS.      |

## 6. Characteristics & considerations

- Characteristics:
  - Backward Compatible: A router that supports MP-BGP can still peer with a router that only supports classic IPv4 BGP.
  - Single Session: Reduces overhead and management complexity compared to running multiple BGP instances.
  - Separate RIBs: MP-BGP maintains separate Routing Information Bases (RIBs) for each configured address family.
- Considerations:
  - Policy Complexity: Route-maps and filtering policies must be applied per address family, increasing configuration complexity.
  - Resource Usage: Carrying multiple large routing tables (e.g., full IPv4 and full IPv6 internet tables) consumes significant memory and CPU.

## 7. MP-BGP for IPv6 implementation

- The same BGP session that carries IPv4 routes can also carry IPv6 routes.
- The next-hop for an IPv6 route advertised via MP-BGP is an IPv6 address.
- The `NEXT_HOP` and `NLRI` are carried inside the `MP_REACH_NLRI` attribute.
- Configuration involves two steps:
  1.  Enable the IPv6 unicast address family.
  2.  Activate the IPv6 neighbor under that address family.

## 8. Key related protocols & technologies

- MPLS (Multiprotocol Label Switching): The forwarding plane that often relies on MP-BGP as its control plane for VPNs.
- L3VPN (Layer 3 Virtual Private Network): The primary application that drove the creation of MP-BGP.
- EVPN (Ethernet VPN): A next-generation L2VPN technology that uses MP-BGP for MAC address learning and distribution.
- Route Reflectors: Crucial for scaling iBGP within an AS for multiple address families.

## Quick reference

- Command Context: Configuration typically occurs within `address-family ipv6 unicast` or `address-family vpnv4` sub-mode.
- Next-Hop Behavior: For IPv6 over an IPv4 session, the next-hop is often represented as an IPv4-mapped IPv6 address (e.g., `::FFFF:203.0.113.1`) by default, but can be changed to a pure IPv6 address.
- Peering: eBGP and iBGP rules apply exactly as they do in classic BGP, but within each address family.