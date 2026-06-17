# Choosing what to touch

Most of an inter-domain operation is deciding what not to touch. Before that decision makes sense, a few
objects do.

![the logical structure: the objects, the two exploitable rules, and the three selection criteria that converge on a workable target.](/_static/images/01-target-selection.png)

## The objects

Inter-domain routing moves traffic between autonomous systems. An autonomous system (AS) is one network under
one administration, with a number: `AS64500`, `AS3356`. Each AS announces the IP prefixes it holds, such as
`203.0.113.0/24`, a block of 256 addresses. A BGP route is the claim "this prefix is reachable through this
sequence of ASes", and the last AS in that sequence is the origin, the network asserting it holds the block.

Two rules do most of the work, and both are exploitable rather than broken.

Longest-prefix match: a router always prefers the most specific matching prefix. A `203.0.113.0/25` wins the
lower 128 addresses over a `203.0.113.0/24` regardless of path length, policy, or anything else. Specificity
is absolute.

Trust by default: a plain BGP announcement carries no proof the origin is entitled to the prefix. Whether a
neighbour accepts it comes down to that neighbour's filters and habits, not to the protocol.

A target tends to be workable when three things line up: room in the table, slack in the watchers, and
traffic worth the risk.

## Room in the table

See who originates a prefix, and whether there is space beneath it:

```
whois -h whois.radb.net 203.0.113.0/24
```

```
route:    203.0.113.0/24
origin:   AS64500
source:   RADB
```

The bgp.tools per-prefix page shows the same registry view plus what the global table currently carries,
including any more-specifics already present:

```
https://bgp.tools/prefix/203.0.113.0/24
```

A `/24` with nothing more specific underneath leaves room for a `/25`. Whether that `/25` would be accepted
is a question of coverage, which [surveying the defences](coverage-survey.md) takes up. The point at this
stage is only that the room exists.

## Slack in the watchers

Heavily watched prefixes, large banks and the hyperscale clouds, carry alerting and contracts that turn an
anomaly into a phone call within minutes. Regional ISPs, NGOs and municipal networks more often notice splits
rather than outages, and notice them late. A cheap proxy for scrutiny is the customer cone: how many networks
sit beneath an AS, and where it ranks.

```
https://asrank.caida.org/asns/64500
```

A small cone with no obvious newsworthiness usually travels with thin monitoring.

## Traffic worth the risk

Value is metadata as often as content: who talks to whom, when, how often. A prefix carrying VPN
concentrators, VoIP, or control links shows strain under small changes, while a static web host shrugs them
off. The character of the traffic decides whether a subtle nudge is worth more than a loud one.

Selection done well means the announcement, when it comes, is unremarkable.
