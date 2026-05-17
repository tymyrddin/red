# Border Gateway Protocol (BGP)

A global routing system built on trust, making it vulnerable to hijacking and misdirection.

## The role of BGP

- Inter-Domain Routing: the protocol that glues the internet together by exchanging routing and reachability information between Autonomous Systems (ASes).
- Path Vector Protocol: makes routing decisions based on paths, network policies, and rule-sets configured by network administrators.
- The Protocol of Policy: its primary goal is not to find the shortest path, but the best path according to business and policy agreements.

## Key BGP concepts and terminology

- AS (Autonomous System): a collection of IP networks and routers under the control of a single entity (e.g., an ISP, a large company). Identified by a unique ASN.
- ASN (Autonomous System Number): a 16-bit (1–65535) or 32-bit number assigned to an AS. Public ASNs are globally unique.
- NLRI (Network Layer Reachability Information): the IP prefix (e.g., `192.0.2.0/24`) being advertised.
- Path Attributes: characteristics of a BGP route used for path selection (e.g., `AS_PATH`, `NEXT_HOP`, `LOCAL_PREF`).
- Peering: the BGP session established between two routers in different ASes.
- iBGP vs. eBGP:
  - eBGP: runs between different ASes. Typically, peers are directly connected.
  - iBGP: runs between routers within the same AS. Used to synchronise BGP information internally. Peers do not need to be directly connected (requires an IGP like OSPF).

## The BGP path selection algorithm

A router evaluates multiple paths to the same prefix and selects the best one in this order:

1. Highest `LOCAL_PREF`: manually set within an AS; indicates preferred exit point.
2. Shortest `AS_PATH`: the fewest number of AS hops.
3. Lowest `ORIGIN` type: prefer IGP over EGP.
4. Lowest `MED` (Multi-Exit Discriminator): a suggestion to neighbouring ASes about which path to use to enter your AS.
5. eBGP path over iBGP path: prefer externally learned paths.
6. Lowest IGP metric to `NEXT_HOP`: prefer the path with the closest next-hop router.
7. Oldest route: for stability.
8. Lowest Router ID: a tie-breaker.

## Common BGP session types and relationships

| Type                   | Description                                                                                                                                               | Typical Setup           |
|:-----------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------|
| Provider-Customer      | Customer pays provider for internet access. Provider announces a default route to customer and announces customer's prefixes to the rest of the internet. | `customer` → `provider` |
| Peer-to-Peer (Peering) | Two ASes agree to exchange traffic directly for their customers only (no transit). Often done at internet exchanges (IXPs).                               | `peer` ↔ `peer`         |
| Transit                | An AS pays another AS for full internet routing table access.                                                                                             | `customer` → `provider` |

## Key BGP-related protocols and tools

- TCP/179: BGP uses TCP for reliable, connection-oriented sessions.
- IGP (OSPF, IS-IS): required inside an AS for iBGP to establish sessions between non-directly connected routers and to find the best path to the BGP `NEXT_HOP`.
- Route Servers: used at IXPs to simplify multilateral peering (one BGP session instead of many).

## Characteristics and security concerns

- Characteristics:
  - Incremental and triggered updates (only sends changes).
  - Very scalable due to its design (only carries best path).
  - Convergence is slow compared to IGPs.
- Security concerns:
  - Hijacking: a malicious or misconfigured AS announces prefixes it does not own, diverting traffic.
  - Route Leaking: an AS improperly propagates more specific routes it learned from one provider to another.
  - IP Prefix De-aggregation: announcing many specific subnets can overwhelm router memory.
  - Session Resets: attackers can spoof TCP RST packets to tear down BGP sessions.

## BGP for IPv6 (MP-BGP)

- Protocol: Multiprotocol BGP (MP-BGP) extensions (RFC 4760) are used. It is the same BGP protocol with additional capabilities.
- Address Family: BGP sessions carry multiple address families (e.g., IPv4 Unicast, IPv6 Unicast, VPNv4).
- Configuration: a single BGP session can exchange both IPv4 and IPv6 routes simultaneously.
- NLRI: advertises IPv6 prefixes (`2001:db8::/32`) instead of IPv4 prefixes. Uses different path attributes for IPv6 (e.g., `MP_REACH_NLRI`).

## Quick Reference

- Well-Known Communities: `no-export` (do not leave this AS), `no-advertise` (do not advertise to any peer).
- Session States: `Idle` → `Connect` → `Active` → `OpenSent` → `OpenConfirm` → `Established`.
- Keepalive/Hold Timers: typically 60/180 seconds.
