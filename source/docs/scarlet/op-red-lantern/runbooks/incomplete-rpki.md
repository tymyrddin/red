# Incomplete RPKI deployment → opportunistic prefix hijack

This is not a crypto attack. RPKI's signatures are sound; the gaps are in who has signed and who bothers to
check. A route only meets RPKI where the prefix carries a ROA and every network on the path enforces Route
Origin Validation, and in 2026 neither holds everywhere. The attack lives in that shortfall: announce the
target prefix from an unauthorised origin, and it reads `not-found` rather than `invalid`, or it reads
`invalid` and travels anyway through every AS that does not enforce. As with the other chains, the redirection
is entirely a control-plane affair, no packet is touched, and the announcement itself is ordinary.

## Reading the coverage

The groundwork is a survey of RPKI state on and around the target, all of it public. A validator's output
lists the signed prefixes and their maximum lengths, and bgp.tools shows the per-prefix validity at a glance:

```
routinator vrps --format csv | grep 203.0.113
```

An absent line means the prefix is unsigned. The choice of target then comes down to which of two gaps the
prefix offers, and the announcement is shaped to suit.

## Two gaps, not one

RPKI fails the defender in two distinct ways, and the attack uses whichever the target presents.

The coverage gap is an unsigned prefix. Announced from any origin it stays `not-found`, and `not-found` is
carried almost everywhere, since the common posture among networks that validate is to drop `invalid` and
accept the rest. A network can run validation diligently and still pass the route, because there is nothing
for it to fail against. This is the softest case.

The enforcement gap is the larger one. Route Origin Validation is far from universal: many networks do not run
it, and some only log the result. So a route that validates as `invalid`, a forged origin on signed space, or
a more-specific beyond a ROA's max length, still propagates through every AS that does not enforce, and reaches
the ones that do not check. An `invalid` verdict does not delete a route; it only shrinks the set of networks
willing to carry it.

Given the choice, the unsigned target is the cleaner opportunity. A `not-found` route raises no validation
failure anywhere, while an `invalid` route leaves evidence wherever validation is observed, even where it is
not enforced. So the coverage gap is the quieter of the two even when both would carry the traffic, and the
enforcement gap is the fallback for a target that is already signed.

## Reading the enforcement

Coverage is published; enforcement is not. No registry lists which networks drop `invalid`, so where the
target is signed and the play rests on the enforcement gap, enforcement has to be estimated rather than looked
up. A few readings converge on an answer.

Validity from several vantage points. A route already known to be `invalid` somewhere in the table can be
watched across looking glasses and collectors in different networks: wherever the invalid route is still
visible, the path to that vantage did not drop it. Comparing many vantages sketches the rough shape of who
enforces and who does not.

A controlled test. Announcing a deliberately `invalid` route from address space the attacker already holds,
then watching it across RIPE RIS, RouteViews and public looking glasses, shows directly which providers carry
invalids, without touching anyone else's prefix.

The published record. ROV deployment studies, MANRS membership, and operator-list write-ups name enforcing and
non-enforcing networks in the open, and past incidents where an invalid route spread well beyond the enforcing
networks tend to name the gaps outright.

The victim's own paths. The estimate that counts is local to the target: the transit providers carrying the
victim are the ones whose posture decides the attack. A single enforcing provider close to the victim blunts
it; a large non-enforcing transit on the path carries it a long way. The aim is not a master list of
non-enforcing ASes but an estimate good enough to judge whether the gap is worth the attempt.

## The announcement

The origination is the same as any other: bring the prefix into the local table, then hand it to BGP with a
`network` statement. From the attacker's AS:

```
ip route 203.0.113.0/24 Null0

router bgp 64511
 address-family ipv4 unicast
  network 203.0.113.0/24
```

`Null0` discards the captured traffic; an interception host in its place forwards it on. The UPDATE is
well-formed, and the origin is unauthorised but not cryptographically blocked, so nothing in the protocol
refuses it. What decides its reach is not the announcement but the coverage and enforcement around the prefix.

## The sequence as performed

1. Reach the router. `vtysh` on whatever position carries the origin, an owned AS, a peering, or the like.
2. Confirm the coverage still holds. `routinator vrps --format csv | grep 203.0.113`, or the bgp.tools RPKI
   view, to check the prefix is still `not-found`, or that the paths that matter still do not enforce.
3. Make the change. `configure terminal`, the `ip route` and `network` lines above, then `end` and `write
   memory`.
4. Confirm it originates and leaves. `show ip bgp 203.0.113.0/24` reads as locally originated, and `show ip
   bgp neighbor 198.51.100.1 advertised-routes` shows it going to the upstream.
5. Watch where it is accepted. The public collectors, RIPE RIS and RouteViews, and per-AS RPKI views show how
   far the route spread and which networks took it. Acceptance maps onto the non-enforcing paths, so the
   picture is partial by nature.

## Partial but persistent

The hijack succeeds unevenly, which is both its signature and its cover. Some regions follow the forged route,
others the legitimate one, and the split tracks which upstreams enforce. Global success is not the aim: partial
capture is often enough, and detection thresholds are commonly tuned for outages rather than splits, so a quiet
partial hijack can sit for a long time without tripping anything.

## Why defenders struggle

In the `not-found` case nothing is marked `invalid`, so no alarm fires on validity at all. Operators looking at
their own slice see it working and reasonably conclude the trouble is someone else's. Blame is diffuse by
construction: the victim did not publish a ROA, the attacker only announced into the space that left, and each
network accepted what its policy allowed. Everyone is within spec, and coordination drags while time passes.

## What closes it

Two acts, and one alone is not enough. The victim signing the prefix, with a tight max length, moves it out of
`not-found` and makes a forged origin `invalid`. That only bites where the networks downstream enforce Route
Origin Validation, so the rest of the fix belongs to the transit ecosystem actually dropping `invalid` rather
than logging it. ASPA and path validation extend the same idea to the AS_PATH. Until enforcement is the default
rather than the exception, a signed prefix is protected only along the paths that check: RPKI reduces the risk,
it does not erase it, `not-found` is not the same as safe, and a standard that is not universally enforced is a
suggestion, not a shield.

## Related

- [BGP hijacking & route leaks](../../../in/network/roots/ip/bgp-hijacking.md): general IPv4 context
- [IPv4 prefix hijacking](../../../in/network/roots/bgp/prefix-hijack.md): specific mechanics
