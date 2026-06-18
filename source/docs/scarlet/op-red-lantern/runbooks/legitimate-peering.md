# Legitimate peering → more‑specific prefix hijack

This is the loudest BGP attack that still counts as quiet. An AS announces a more-specific of a prefix it does
not hold, a `/24` carved out of someone's `/20`, and longest-prefix match hands it the traffic, because a
router always prefers the most specific route that matches, regardless of path, policy, or origin. The
redirection lives entirely in the control plane: no packet is touched, the traffic moves only because a
narrower route won. Unlike a false origin from a compromised customer, the position here is taken in the open:
a real BGP peering, acquired by the rules, used to say one thing it was never meant to.

## A peering acquired by the rules

The announcement needs a session some neighbour will carry, and here it is obtained rather than stolen.
Internet Exchange membership, a reseller or transit contract, or lab and research network access each provide
one, and none calls for deception at this stage. What makes the position useful is the state of the filters on
the other side. Peering filters are often permissive or minimal, resting on assumptions rather than checks:
that a peer announces only what it holds, that the prefix-list someone generated months ago is still right,
that the automation building filters from IRR data caught everything worth catching. Each assumption is a
place a more-specific can pass unremarked.

The opening appears where the peer's filter describes what the AS is expected to announce only in broad terms,
or has not been rebuilt since the last allocation and policy changes. A newly originated more-specific then
passes for one of a few reasons: it falls inside a larger authorised aggregate the filter already permits, the
filter was generated from stale registry data, or no prefix filter exists on the session at all. None of this
depends on breaking the session. It depends on the session already trusting more than it verifies.

## The more-specific announcement

The victim originates, say, `203.0.112.0/20`. The attack announces a contained `203.0.113.0/24` from the
peering AS. The prefix has to sit in the local table first, then a `network` statement hands it to BGP, the
same origination mechanic as any other route. On FRR:

```
ip route 203.0.113.0/24 Null0

router bgp 64511
 address-family ipv4 unicast
  network 203.0.113.0/24
```

`Null0` blackholes the captured range; an interception host in its place forwards it on. The UPDATE is
syntactically valid and passes basic filtering, and where no ROA covers the space the `/24` reads `not-found`
rather than `invalid`. A covering ROA changes that: a more-specific beyond the ROA's max length, or from an
origin the ROA does not name, turns `invalid`, and an enforcing network drops it. A clean run therefore
depends on unsigned space or a path with no enforcement on it, which is the reading the coverage survey
produces.

## The sequence as performed

The router here is the attacker's own, legitimately peered, so reaching it needs no compromise:

1. Reach the peering router. `vtysh` on the AS's own kit; the session is held by right, not stolen.
2. Check the ground. `show ip bgp summary` for the peering session at `198.51.100.2`, and `show ip bgp
   203.0.112.0/20` to confirm the victim's block and that no more-specific is present under it yet.
3. Make the change. `configure terminal`, the `ip route` and `network` lines above, then `end` and `write
   memory`.
4. Confirm it originates and leaves. `show ip bgp 203.0.113.0/24` reads as locally originated, and `show ip
   bgp neighbor 198.51.100.2 advertised-routes` shows the `/24` going to the peer. A `network` statement
   advertises as soon as the route is in the table, so no soft-clear is needed.
5. Watch it spread. A single looking glass is only the first check. An attacker keeps an eye on the public
   collectors, RIPE RIS and RouteViews, and on route-server and looking-glass views in several regions, to see
   how widely the `/24` is being accepted and where it is winning its 256 addresses out of the `/20`.
   Propagation is uneven and gradual, so the live question is not whether the route appeared but how far it has
   reached, while the rest of the block carries on as before.

## Why it wins, and how far

Longest-prefix match is the strongest rule in IP routing, and it is not a flaw. A router forwarding a packet
picks the most specific route that matches, so a `/24` beats the covering `/20` for its range outright. AS_PATH
length does not enter into it, local preference does not enter into it, and routing policy bows to specificity.
That is also the limit of the blast radius: only traffic for the more-specific range moves, and the rest of
the `/20` behaves exactly as before. The narrowness is the point. It keeps the attack partial, regional where
propagation is uneven, and easy to deny.

Longest-prefix match decides only among the routes a network has accepted, though, and acceptance is the part
that varies. Quite apart from RPKI, many operators filter unexpected more-specifics on their own, dropping a
`/24` that falls outside the prefix lengths or allocation boundaries their filters expect, so the `/24` wins
where it is carried but is simply absent elsewhere. The reachable surface is smaller and more
policy-fragmented than the rule alone suggests, which is why the question stays how far it reached, not whether
it won.

## Why detection lags

No outage is required and none occurs. The legitimate origin stays visible throughout, monitoring sees both
routes, and nothing reads as down: services are up but slow, and users complain vaguely. To a defender the
shape is hard to tell from ordinary traffic engineering, since more-specifics are announced legitimately every
day and exchange participants do exactly this as routine. The behaviour is familiar, so the response
hesitates.

## What closes it

A ROA on the victim's block with a tight max length is the direct counter: it makes every more-specific the
attacker might announce `invalid`, and an upstream or exchange enforcing origin validation drops them. Where
the exchange or peer builds prefix-lists from current, RPKI-checked IRR data rather than a stale `as-set`, the
`/24` never passes the filter at all. Absent both, the attack leans on the one rule nothing can switch off:
longest-prefix match is absolute, and trust plus specificity beats good intentions. Perfect policy, monitoring
and paperwork still leave a `/24` able to ruin an afternoon.

## Related

- [BGP hijacking & route leaks](../../../in/network/roots/ip/bgp-hijacking.md): general IPv4 context
- [IPv4 prefix hijacking](../../../in/network/roots/bgp/prefix-hijack.md): specific mechanics
