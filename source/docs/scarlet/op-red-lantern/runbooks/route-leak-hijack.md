# Route leak escalating into an effective hijack

A route leak is a hijack that forges nothing. The origin AS stays correct, every AS_PATH is valid, and no
UPDATE breaks a rule. What the attacker breaks is export policy: a route learned from one neighbour is
announced onward to another it was never meant to reach, and that crossing is the whole event. As with a false
origin, the announcement is trivial, and the redirection lives entirely in the control plane: no packet is
touched, the traffic moves only because the leaked route won the selection. The position is an AS that sits
between the right neighbours, and the move is choosing to carry a route across a boundary that policy is meant
to hold.

## An AS with more than one relationship

A leak needs an AS with at least two kinds of neighbour, an upstream and a peer or customer, because a leak is
the act of carrying routes across between them. The requirement is relationships, not sophistication. Small
ISPs, hosting providers, research networks and regional transit customers all fit, and the operative weakness
is rarely a single flaw. It is entropy: copy-pasted configs, "temporary" exceptions that outlived their
reason, staff turnover, and automation without guardrails. The position is operated or compromised; either
way, the attacker ends up able to edit the AS's outbound BGP policy, which is all the leak needs.

## Crossing the boundary on purpose

Valley-free routing expects an AS to announce, to a provider or a peer, only the routes it or its customers
originate, and to keep provider- and peer-learned routes to itself. That expectation is enforced on the export
side, commonly by tagging routes with a community at import (customer `64511:100`, peer `64511:200`, provider
`64511:300`) and permitting only the customer tag outbound to a peer or a provider. A leak is the announcement
that ignores the boundary, and an attacker operating the AS does not wait for the guard to fail by accident:
they remove or bypass it for the routes they want moved.

Take AS64511, which buys transit from provider AS64509 and peers with AS64510. It learns the target prefix
`203.0.113.0/24`, originated by AS64500, from its provider, and would normally keep that provider-learned route
to itself. The deliberate leak announces it to the peer instead, where AS64511 now reads as a short, direct
path to the target. Selectively, that is one prefix-list and one outbound route-map:

```
ip prefix-list LEAK seq 5 permit 203.0.113.0/24

route-map TO-PEER permit 10
 match ip address prefix-list LEAK

router bgp 64511
 address-family ipv4 unicast
  neighbor 198.51.100.2 route-map TO-PEER out
```

This advertises a provider-learned prefix to a peer: a textbook valley-free violation, made surgically. The
peer, and anyone preferring the peer path, now sends the target's traffic through AS64511. The same crossing
runs in other directions too, peer routes announced to an upstream, or an upstream's routes to another, milder
or broader by turn. The blunt version is to drop the outbound filter entirely and leak the whole table at
once: louder, quick to trip the maximum-prefix limit on the receiving side, and obvious as a leak on sight.
Moving only the wanted prefixes sits closer to noise and lasts longer.

From BGP's side each of these UPDATEs is valid: attributes normal, AS_PATH intact, no rule broken. The control
plane has already failed, quietly, because the boundary that gave way was policy rather than protocol.

## The sequence as performed

The route-map above does nothing on its own until it is pushed to the session. From control of AS64511's
router, the run could look something like:

1. Reach the router. `vtysh` on the access the position bought.
2. Check the ground. `show ip bgp summary` for the provider and peer sessions; `show ip bgp 203.0.113.0/24` to
   confirm the target is present and learned from the provider (AS64509); `show ip bgp neighbor 198.51.100.2
   advertised-routes` to confirm it is not already going to the peer.
3. Make the change. `configure terminal`, the prefix-list and route-map above and the outbound `route-map ...
   out` on the peer, then `end` and `write memory`.
4. Push it. `clear bgp ipv4 unicast 198.51.100.2 soft out`. This is the step the config alone leaves out: an
   outbound policy change does not re-advertise to an established session by itself.
5. Confirm the leak left. `show ip bgp neighbor 198.51.100.2 advertised-routes` now lists `203.0.113.0/24`.
6. Watch and dispose. The looking glass or telemetry shows the peer and its dependents preferring AS64511; the
   still-valid provider path is the onward hop for interception, or the route is discarded to blackhole.

## Why the leaked path wins

A leak redirects traffic only where other networks come to prefer it. AS64511 often sits on a shorter AS_PATH
to the target than the legitimate route carries, or lands on the preferred side of a peer relationship, or
simply offers a way around congested transit. Where it does, those networks select it as best path and traffic
shifts onto it. The origin AS is still AS64500 and no prefix was forged, yet the legitimate path is bypassed
and AS64511 carries traffic that was never meant to pass through it.

Trouble in BGP tends to arrive this way, by escalation rather than as a sudden outage. A quiet leak draws a
little traffic, then more as further networks come to prefer the path, and only late does the shape read as a
hijack at all. The catastrophe is the end of the slope, not the start.

## What arrives, and what becomes of it

Because the leaking AS does hold a working route to the target, through its provider, the redirected traffic
can be forwarded on to the real destination after it is read or altered: a leak yields interception almost for
free, with the legitimate path serving as the onward route. Discarding it instead blackholes the target;
withdrawing and re-announcing on a cycle keeps the route flapping. The visible symptoms are the ordinary ones
of misrouted traffic: latency spikes, packet loss, regional brownouts, and a wave of "the internet is slow"
tickets that name nothing useful.

## Sustaining it undercover

An accidental leak and a deliberate one look identical on the wire, which is the appeal, and the attacker
leans on it. The leak can be re-announced after the receiving side filters it, combined with other
announcements, and timed to land during someone else's incident response, when attention is elsewhere. The
cover comes for free, since "we are investigating", "unexpected propagation" and "policy misinterpretation"
are the things a genuinely confused operator would also say. The chain rewards cover over cleverness.

## Why it is hard to diagnose

The leaking AS looks legitimate because it is. It genuinely learned the routes and genuinely announced them,
and nothing is spoofed. Attribution is awkward in a different way from a false origin: the open question is not
who but what, whether mistake, negligence, or intent, and because the three read identically from outside,
early response tends to be hesitant, since no operator wants to accuse the wrong party. The internet does not
separate malice from misconfiguration; it carries both at line speed.

## What closes it

Outbound filters that enforce the valley-free shape, the community-tagging guard above among them, stop the
leak at its source. A maximum-prefix limit caps a session before a full-table leak travels far. ASPA
(Autonomous System Provider Authorisation), the RPKI object in which a network declares its providers, lets a
path that violates the declared relationships be flagged as it propagates, and peer-locking with well-kept
IRR-based filters on the receiving side catches much of the rest. Where export policy is left to habit, the
leak stays one config slip away, which is exactly why a deliberate one hides so well among the accidental
ones.

## Related

- [BGP hijacking & route leaks](../../../in/network/roots/ip/bgp-hijacking.md): general IPv4 context
- [IPv4 prefix hijacking](../../../in/network/roots/bgp/prefix-hijack.md): specific mechanics
