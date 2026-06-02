# BGP hijacking: the IP layer

*IP addressing perspective. Canonical BGP attack surface: [Rootways: BGP](../bgp/tree.md).*

IP prefix ownership is asserted, not proven. The routing control plane accepts announcements from any AS, making reachability itself the attack primitive: control what routes exist, and control where traffic flows.

## Attack tree

```text
1. IP routing control plane manipulation [OR]

    1.1 Prefix ownership gaps [OR]

        1.1.1 Exact-prefix announcement
            1.1.1.1 Announce a legitimate prefix from an AS that does not own it
            1.1.1.2 Exploit absent ROA validation at receiving ASes

        1.1.2 Sub-prefix announcement
            1.1.2.1 Announce a more specific prefix to win longest-match selection
            1.1.2.2 Attract traffic intended for the covering prefix

        1.1.3 Unallocated space squatting
            1.1.3.1 Announce unallocated IP space to create reachable infrastructure
            1.1.3.2 Exploit absence of a legitimate owner who might notice the announcement

    1.2 ASN validation absence [OR]

        1.2.1 Origin AS forgery
            1.2.1.1 Announce a prefix with a forged origin AS
            1.2.1.2 Exploit incomplete RPKI ROA coverage at receiving ASes

        1.2.2 AS path manipulation
            1.2.2.1 Shorten AS path to increase route preference
            1.2.2.2 Prepend fake ASNs to obscure origin or create plausible deniability

    1.3 Reachability as disruption primitive [OR]

        1.3.1 Traffic blackholing
            1.3.1.1 Announce prefix with null next-hop to discard traffic
            1.3.1.2 Target service prefixes to create availability denial without physical action

        1.3.2 Route leak exploitation
            1.3.2.1 Re-advertise learned routes beyond intended scope
            1.3.2.2 Cause transit traffic to pass through an unintended AS
```

## Why it works

IP addresses carry no cryptographic binding to their legitimate holder. The routing control plane propagates reachability information based on configuration and peering policy, and RPKI provides origin validation only for prefixes where a Route Origin Authorisation has been published and where receiving ASes enforce it. Coverage is incomplete and enforcement varies. A more specific or shorter-path announcement may attract traffic regardless of whether the destination is legitimate.

## Operational implications

- Traffic interception at internet scale is achievable without compromising any device on the legitimate path.
- Sub-prefix hijacking is selective: the adversary attracts only the targeted traffic, leaving the rest undisturbed.
- Blackholing produces no exploitable traffic but achieves denial of availability with no physical action required.

## Detection pressures

- Unexpected changes to the origin AS for a known prefix appear in BGP looking glasses and route monitoring services.
- Sub-prefix announcements for prefixes not previously subdivided create an anomalous more-specific entry in the global routing table.
- Traffic volume drops on the legitimate prefix path may surface in flow data when diversion is active.

## Related

- [Rootways: BGP attack tree](../bgp/tree.md)
- [Rootways: BGP prefix hijacking](../bgp/prefix-hijack.md)
- [Rootways: BGP path manipulation](../bgp/path-manipulation.md)

## Counter moves

BGP hijacking: the IP layer is what this page works through. Anti-spoofing filters such as BCP 38, and segmentation, close it. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
