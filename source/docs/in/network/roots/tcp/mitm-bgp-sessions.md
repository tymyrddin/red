# Man-in-the-middle BGP sessions

*TCP transport perspective. Canonical BGP attack surface: [Rootways: BGP](../bgp/tree.md).*

An on-path position between BGP peers yields the full routing table in plaintext and, where authentication is absent or weak, the ability to modify UPDATE messages without touching either speaker.

## Attack tree

```text
1. On-path interception of BGP sessions [OR]

    1.1 Achieving on-path position [OR]

        1.1.1 Layer 2 redirection
            1.1.1.1 ARP cache poisoning between BGP peers on shared segment
            1.1.1.2 Compromise of switch with SPAN or port mirror access

        1.1.2 Layer 3 redirection
            1.1.2.1 DNS poisoning to redirect BGP peer address resolution
            1.1.2.2 Compromise of an intermediate routing device

        1.1.3 IXP fabric exploitation
            1.1.3.1 Exploit unencrypted exchange point connections
            1.1.3.2 Access shared switching infrastructure at an internet exchange

    1.2 TCP session interference [OR]

        1.2.1 Session hijacking
            1.2.1.1 Observe sequence numbers from on-path position
            1.2.1.2 Inject or modify BGP UPDATE messages in-stream

        1.2.2 Authentication downgrade
            1.2.2.1 Force fallback from TCP-MD5 to unauthenticated session
            1.2.2.2 Exploit misconfigured or absent TCP-AO

        1.2.3 TCP-AO bypass
            1.2.3.1 Extract authentication keys from compromised router memory
            1.2.3.2 Exploit cryptographic implementation weaknesses in TCP-AO
```

## Why it works

BGP was designed for a trust environment of co-operating ISPs. Sessions often run without per-packet authentication, and even MD5-authenticated sessions are readable by any device on the path. Internet exchanges concentrate many peers on shared Layer 2 fabric, making a single on-path position disproportionately valuable.

## Operational implications

- Passive observation of the full routing table reveals peering relationships, traffic volumes, and prefix ownership without generating BGP-layer events.
- In-stream UPDATE modification allows route injection without touching either BGP speaker.
- A compromised IXP position may yield simultaneous access to multiple peering sessions.

## Detection pressures

- ARP cache poisoning between directly peered routers generates anomalous ARP traffic that link-layer monitoring may catch.
- Abrupt sequence number discontinuities on an established session may indicate active injection.
- Unexpected latency increases on stable sessions surface if timing baselines exist.

## Related

- [Rootways: BGP attack tree](../bgp/tree.md)
- [BGP session manipulation](bgp-session-manipulation.md)
- [Router TCP stack exploitation](tcp-stack-on-bgp-router.md)
