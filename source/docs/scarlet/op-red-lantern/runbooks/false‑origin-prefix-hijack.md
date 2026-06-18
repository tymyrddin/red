# Compromised customer → false‑origin prefix hijack

A false origin is the plainest BGP attack there is: an AS announces a prefix it is not authorised to
originate, and the announcement is believed because nothing in the protocol asks for proof. The whole of it
lives in the control plane. No packet is touched and no payload inspected to move the traffic; it moves because
a forged route won the selection, and what then happens to the diverted packets is a separate, later choice.
The announcement is never the interesting part. The work is getting into a position where an upstream carries it without a second look, which
is why this chain starts at a customer network rather than at a router.

## A customer that is already trusted

The announcement has to leave from somewhere an upstream already accepts routes from, and a customer AS is the
natural place. The relationship is established, the customer filters are often loose, and an upstream's
instinct is to believe the network it is paid to carry. Reaching that position rarely calls for router
exploitation. The routing configuration of a small AS tends to change through the same soft surfaces as
anything else: a customer-portal credential, an automation pipeline (the CI job or API token that pushes router
config), an insider, or access inherited through an acquisition or a lapsed contract. Small ISPs, hosting
providers, and enterprises running their own AS make the easier marks, less for any single weakness than for
thin monitoring and the long gap between someone noticing and someone acting.

What the position buys is the right to send updates the upstream treats as routine. Everything after it is one
UPDATE.

## The announcement

With control of the customer's router, the attack itself is a single change: originate the target's prefix as
though it were the customer's own. The prefix has to sit in the local table first, usually as a static route,
and a `network` statement then hands it to BGP. On FRR:

```
ip route 203.0.113.0/24 Null0

router bgp 64511
 address-family ipv4 unicast
  network 203.0.113.0/24
```

The two lines are a pair: BGP's `network` statement originates a prefix only when a matching route already
exists in the routing table, so the static route is what brings the prefix into the table for BGP to advertise.
The `Null0` next hop blackholes the captured traffic; pointing the static route at an interception host instead
forwards it on. The prefix belongs to another organisation, the origin AS is now `64511` rather than the
network authorised to originate it, and from BGP's point of view the UPDATE is unremarkable.

Two choices set the blast radius. Announcing the victim's exact prefix puts the false origin into competition
with the real one, where the winner turns on path length and local preference, so the hijack stays partial and
regional. Announcing a more-specific, a `/24` carved out of a `/20` the victim originates, wins everywhere
longest-prefix match reaches, regardless of path or policy, because specificity outranks all of it. The
more-specific is the stronger move and the louder one: a fresh `/24` appearing under a stable `/20` is close to
the canonical shape a detector watches for.

## The sequence as performed

The config above is the control-plane edit, not the whole of it. From the access the position bought, the run
is roughly:

1. Reach the customer's router. On a lab this is `vtysh` on the host the access lands on, with whatever the
   credential grants; on real kit it is the same login the portal or pipeline exposed.
2. Check the ground. `show ip bgp summary` for the upstream session at `198.51.100.1`, and `show ip bgp
   203.0.113.0/24` to confirm nothing local already originates it.
3. Make the change. `configure terminal`, the `ip route` and `network` lines above, then `end` and `write
   memory`.
4. Confirm it originates and leaves. `show ip bgp 203.0.113.0/24` now reads as locally originated, and `show
   ip bgp neighbor 198.51.100.1 advertised-routes` shows it going to the upstream. A `network` statement
   advertises as soon as the route is in the table, so no soft-clear is needed here.
5. Watch from outside. A looking glass or the lab's telemetry shows the false origin chosen along whichever
   paths it wins, and traffic for the range begins landing where the static route points: `Null0` to drop it,
   or the interception host to read it.

Announcing a more-specific is the same run with a longer prefix in the `ip route` and `network` lines.

## Why the upstream carries it

The upstream accepts the route for the same reasons the position was worth taking. Its prefix-list for the
customer is missing, stale, or generated from a loose `as-set` that already lists more than the customer
announces. RPKI offers little where the victim prefix carries no ROA: the route reads `not-found` rather than
`invalid`, and a network that drops invalids commonly still carries not-found. The relationship does the rest,
since a customer that has never caused trouble is believed out of habit.

Where a ROA does cover the prefix and the false origin contradicts it, the route turns `invalid`, and an
upstream enforcing origin validation drops it at that hop. A clean false origin therefore depends on a prefix
that is unsigned, or on a path with no enforcement along it, which is the reading the coverage survey produces
before any of this begins.

## Propagation and effect

Once the upstream accepts, the route travels like any other. Other networks learn the false origin, some select
it as best path, and no alarm necessarily fires. What happens to the redirected traffic is a separate choice:
drop it, forward it to the real destination after reading or changing it (interception, which needs a return
path to the genuine origin that does not loop back through the hijack), or announce and withdraw on a cycle to
keep the route flapping. One announcement supports all three; only what waits at the receiving end differs.

Impact is usually partial. Only traffic whose best path now prefers the false origin moves, which might be a
region, a handful of networks, or nearly everything for a more-specific, while the rest carries on as before.
The partiality is part of why it stays quiet.

## Why it is hard to call

A false origin looks much like a misconfiguration, because most of the time that is what it is. Fat-fingered
originations happen routinely, the origin AS is a real and legitimate customer, so early attribution leans
towards accident and blame is slow to converge. Monitoring may see both origins at once, a MOAS
(multiple-origin AS) event, without being able to say which is the wrong one. That ambiguity, rather than any
stealth in the announcement, is what tends to buy the attack its lifespan.

## What closes it

A ROA on the victim prefix, paired with an upstream that actually enforces origin validation, turns the false
origin from not-found into invalid and drops it at the first enforcing hop. A tight, RPKI-checked customer
prefix-list does the same work a layer out. Where neither is in place the announcement keeps working, which in
2026 is still common enough to be worth the attempt.

## Related

- [BGP hijacking & route leaks](../../../in/network/roots/ip/bgp-hijacking.md): general IPv4 context
- [IPv4 prefix hijacking](../../../in/network/roots/bgp/prefix-hijack.md): specific mechanics
