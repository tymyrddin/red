# Border Gateway Protocol (BGP) notes

A global routing system built on trust, making it vulnerable to hijacking and misdirection.

## 1. The role of BGP (The "Why")

- Inter-Domain Routing: The protocol that glues the internet together by exchanging routing and reachability information between Autonomous Systems (ASes).
- Path Vector Protocol: Makes routing decisions based on paths, network policies, and rule-sets configured by network administrators.
- The Protocol of Policy: Its primary goal is not to find the shortest path, but the *best* path according to business and policy agreements.

## 2. Key BGP concepts & terminology

- AS (Autonomous System): A collection of IP networks and routers under the control of a single entity (e.g., an ISP, a large company). Identified by a unique ASN.
- ASN (Autonomous System Number): A 16-bit (1-65535) or 32-bit number assigned to an AS. Public ASNs are globally unique.
- NLRI (Network Layer Reachability Information): The IP prefix (e.g., `192.0.2.0/24`) being advertised.
- Path Attributes: Characteristics of a BGP route used for path selection (e.g., `AS_PATH`, `NEXT_HOP`, `LOCAL_PREF`).
- Peering: The BGP session established between two routers in different ASes.
- iBGP vs. eBGP:
  - eBGP: Runs between different ASes. Typically peers are directly connected.
  - iBGP: Runs between routers within the same AS. Used to synchronize BGP information internally. Peers do not need to be directly connected (requires an IGP like OSPF).

## 3. The BGP path slection algorithm (Decision Process)

A router evaluates multiple paths to the same prefix and selects the best one in this order:
1.  Highest `LOCAL_PREF` (Local Preference): Manually set within an AS; indicates preferred exit point.
2.  Shortest `AS_PATH`: The fewest number of AS hops.
3.  Lowest `ORIGIN` type: Prefer IGP over EGP.
4.  Lowest `MED` (Multi-Exit Discriminator): A "suggestion" to neighboring ASes about which path to use to enter your AS.
5.  eBGP path over iBGP path: Prefer externally learned paths.
6.  Lowest IGP metric to `NEXT_HOP`: Prefer the path with the closest next-hop router.
7.  Oldest route: For stability.
8.  Lowest Router ID: A tie-breaker.

## 4. Common BGP session types & relationships

| Type                   | Description                                                                                                                                               | Typical Setup           |
|:-----------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------|
| Provider-Customer      | Customer pays provider for internet access. Provider announces a default route to customer and announces customer's prefixes to the rest of the internet. | `customer` → `provider` |
| Peer-to-Peer (Peering) | Two ASes agree to exchange traffic directly for their customers only (no transit). Often done at internet exchanges (IXPs).                               | `peer` ↔ `peer`         |
| Transit                | An AS pays another AS for full internet routing table access.                                                                                             | `customer` → `provider` |

## 5. Key BGP-related protocols & tools

- TCP/179: BGP uses TCP for reliable, connection-oriented sessions.
- IGP (OSPF, IS-IS): Required inside an AS for iBGP to establish sessions between non-directly connected routers and to find the best path to the BGP `NEXT_HOP`.
- Route Servers: Used at IXPs to simplify multilateral peering (one BGP session instead of many).

## 6. Characteristics & security concerns (Attack vectors)

- Characteristics:
  - Incremental and triggered updates (only sends changes).
  - Very scalable due to its design (only carries best path).
  - Convergence is slow compared to IGPs (the "slow car" of routing).
- Security Concerns & Attacks:
  - Hijacking: A malicious or misconfigured AS announces prefixes it does not own, diverting traffic.
  - Route Leaking: An AS improperly propagates more specific routes it learned from one provider to another.
  - IP Prefix De-aggregation: Announcing many specific subnets, which can overwhelm router memory.
  - Session Resets: Attackers can spoof TCP RST packets to tear down BGP sessions.

## 7. BGP security mitigations (Defense)

| Mitigation                              | Description                                                                                                        | How it Helps                                                             |
|:----------------------------------------|:-------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------|
| Prefix Filtering (Ingress/Egress)       | Filter routes advertised to/received from peers. Only allow your customer's prefixes (e.g., `allow 192.0.2.0/24`). | Prevents accidental/malicious advertisement of invalid routes.           |
| RPKI (ROA - Route Origin Authorization) | A cryptographic framework where prefix owners sign which ASN(s) are authorised to originate them.                  | Allows routers to validate BGP announcements and reject hijacked routes. |
| BGPsec                                  | Cryptographically signs the entire AS_PATH, proving the path is valid.                                             | Prevents path tampering (more complex to deploy than RPKI).              |
| AS_PATH Filtering                       | Filter routes containing private or unexpected ASNs in the path.                                                   | Helps prevent route leaks from misconfigured peers.                      |
| TTL Security (GTSM)                     | Checks the TTL of incoming BGP packets. Expects a value of 255 (max).                                              | Prevents remote attackers from spoofing BGP packets to peer routers.     |
| Peer Locking                            | Uses a pre-shared key and TCP-AO to authenticate BGP sessions.                                                     | Protects against session spoofing/reset attacks.                         |

## 8. BGP for IPv6 (MP-BGP)

- Protocol: Multiprotocol BGP (MP-BGP) extensions (RFC 4760) are used. It's the same BGP protocol with additional capabilities.
- Address Family: BGP sessions carry multiple "address families" (e.g., IPv4 Unicast, IPv6 Unicast, VPNv4).
- Configuration: A single BGP session can exchange both IPv4 and IPv6 routes simultaneously.
- NLRI: Advertises IPv6 prefixes (`2001:db8::/32`) instead of IPv4 prefixes. Uses different path attributes for IPv6 (e.g., `MP_REACH_NLRI`).

## Quick Reference

- Well-Known Communities: `no-export` (Don't leave this AS), `no-advertise` (Don't advertise to any peer).
- Session States: `Idle` → `Connect` → `Active` → `OpenSent` → `OpenConfirm` → `Established`.
- Keepalive/Hold Timers: Typically 60/180 seconds.

