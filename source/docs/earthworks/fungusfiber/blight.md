# Operation Blight

Operation Blight is the patient cousin of the louder routing exercises against [FungusFiber
Internet](entity.md). Where Toadstool Takeover seizes the registry and Spore Cloud reads the traffic, Blight
leaves nothing its author can be caught holding: it degrades [Fungolia](../fungolia.md)'s connectivity
selectively and deniably, so the trouble reads as a bad season on the mycelium-net rather than a hand on the
routes.

The author is Shadow6, the Borogravian regency's cyber wing, working to its standing doctrine of paralysing
rather than wrecking. During a renegotiation of the Mutually Suspicious Cooperation Accord, Shadow6 wants
Fungolia's table to feel fragile while the talks run, and the trouble gone the moment the point has landed.
Criminals smash; states nudge.

## Positioning

Blight needs no break-in. Shadow6 works from a transit AS that already sits in FungusFiber's dependency graph,
an upstream the frontier's traffic crosses, which the regency operates or quietly holds and which carries
several upstreams of its own so there are choices about how to propagate. The relationships are legitimate,
which is what keeps every move inside the rules. The difference from the capture exercises is intent: Shadow6
steers traffic rather than seizing it, and wants leverage over quality, not a copy of the data. The regency
also needs time, since the campaign is built from small, slow adjustments rather than one decisive
announcement.

## Mapping what Fungolia leans on

Before any route moves, Shadow6 builds a dependency map of FungusFiber from public records, without a packet
sent at it: which upstreams carry the frontier's prefixes, which exchanges are load-bearing, and which flows
are latency-sensitive, the ministry's command channels, voice and control links suffering first under small
changes. RIPE RIS and RouteViews give the control-plane view, historic traceroutes the data-plane one, and
Fungolia's well-documented past outages tend to name the chokepoints outright. The map decides which paths are
worth touching and which would flap harmlessly.

## Steering with AS_PATH, MED, and de-aggregation

Shadow6's first move re-announces a prefix the transit already carries, with the routing attributes adjusted
per neighbour. Prepending the regency's own ASN several times lengthens the path a chosen region sees, and a
longer path sheds traffic to alternatives, while a clean announcement toward another neighbour keeps that path
attractive. On FRR, where the regency's transit is AS64511 and the Fungolian prefix `203.0.113.0/24` is
originated by FungusFiber as AS64500:

```
route-map TO-REGION permit 10
 set as-path prepend 64511 64511 64511

router bgp 64511
 address-family ipv4 unicast
  neighbor 198.51.100.10 route-map TO-REGION out
```

Where the transit shares parallel interconnects with FungusFiber or its upstream, the finer tool is the
Multi-Exit Discriminator. MED is a hint to a single adjacent network about which entry point to prefer, lower
being better; raised on the clean, low-latency links it nudges traffic onto a more circuitous path across the
neighbour's own backbone, adding jitter without changing the global path length. MED is only a hint, though,
compared between entry points from the same neighbour, overridden by local preference before it is weighed, and
freely ignored or stripped by a network that chooses to, so it bites locally rather than globally.

Sharper still is selective de-aggregation: Shadow6 announces a contained more-specific of a carried prefix to a
few peers only, tagged `NO_EXPORT` to keep it inside the receiving AS or `NO_ADVERTISE` to hold it on the
border router it lands on. Longest-prefix match pulls the chosen flows onto the chosen paths while the rest of
the block behaves normally. The result is a fracture rather than an outage: some paths reroute, others do not,
and from Fungolia's side the trouble reads as intermittent and regional.

## Degrading without flapping

The discipline is to stay below the thresholds that would turn the move into an event. Route-flap damping
suppresses a prefix that oscillates quickly, and a sudden withdrawal reads as an outage, so Shadow6 wants
neither. Damping adds a penalty to each change and lets it decay, so changes spaced on the order of the decay
interval rather than minutes never accumulate to the suppression threshold, and the same spacing keeps them
under the alarms a watcher keeps. Damping is unevenly deployed in any case, often disabled or set loose, which
only widens the room. The degradation comes instead from mild, slow effects: a little packet loss, raised
jitter, and path changes that arrive unpredictably.

None of this is a precise dial, and Shadow6 does not pretend otherwise. BGP attributes influence which path
wins; they do not set quality directly, so the degradation is an emergent effect of that selection rather than
a tunable output. A small shift can ripple further than meant, a convergence event or an ECMP reshuffle, and
the feedback returns delayed and partial, since an outside view is only ever a slice. Each pass is an
approximation read back and corrected, closer to nudging a noisy system than turning a knob. The class of
outcome is reliable; the precise figure is not.

## The sequence

A loop run slowly rather than a single edit. Shadow6:

1. Reaches the transit router. `vtysh` on the AS the regency holds; the sessions are legitimate.
2. Confirms the map. `show ip bgp 203.0.113.0/24` and the per-neighbour advertised-routes views, to read how
   the carried prefixes propagate and which neighbour reaches which region.
3. Makes a small change. `configure terminal`, a per-neighbour prepend, a raised MED, or a scoped
   more-specific, then `end` and `write memory`.
4. Pushes it. `clear bgp ipv4 unicast 198.51.100.10 soft out`, since an outbound change reaches an established
   session only on refresh.
5. Reads the effect. The public collectors show the path lengths shift, and traceroutes from several regions
   show which flows lengthened and where loss or jitter rose, while the unaffected regions confirm the
   degradation stayed selective.
6. Adjusts and waits. Tunes the prepend depth or the de-aggregation, spaces the changes out, and keeps every
   move under the damping and alarm thresholds.

## Attribution fog

Nothing about the campaign is technically wrong. The routes are valid, there is no hijack signature, and the
behaviour resembles ordinary congestion or a misconfiguration somewhere upstream. Fungolia's operators argue
along the supply chain, upstream blaming downstream and downstream blaming transit, while Shadow6 says nothing.
The ambiguity is not a side effect; it is the deliverable.

## Signal and reset

Blight runs alongside the Accord talks rather than instead of them. Fungolia notices that services feel
fragile, that reliability dips at inconvenient moments, and that the trouble clears as quietly as it came. The
message needs no communiqué: the connectivity can be touched without being broken. When the talks turn, Shadow6
exits cleanly. The prepends fall away, the more-specifics are withdrawn, the graphs flatten, and what remains
is not an incident with teeth but a residue of unease.

## Switching hats

The defender's-side reconstruction, what removes the room and what catches the move, is in the blue notes on
[inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/): diverse upstreams so no single
chokepoint degrades cleanly, baseline deviation watched rather than only loss of reachability, and
control-plane and data-plane correlation to separate a deliberate reroute from real congestion. Blight is the
case detection alone struggles with, which is why the blue notes meet it with
[posture](https://blue.tymyrddin.dev/docs/counter/inter-domain/posture/) as much as with alarms.
