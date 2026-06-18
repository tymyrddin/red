# Policy trust abuse → preferred‑path hijack

In its cleanest form this chain forges nothing and fails no validation. The origin is correct, every attribute is within policy,
and the attacker holds a right to announce the prefix that the upstream accepts as legitimate, even though the
reachability it describes belongs to someone else. Two things have to be in place: that legitimate-looking
right to announce, and a relationship whose routes the upstream prefers. With both, an announcement crafted to
win selection pulls traffic off its intended path without a single rule being broken. The redirection lives
entirely in the control plane, no packet is touched, and from the outside the network looks healthy
throughout. It works even where origin validation is perfect, because validation has nothing to say about
which valid route wins.

## The right to announce someone else's reachability

The crux is acquired before any attribute is crafted: a way to announce the victim's prefix that the upstream
treats as authorised. The reachability belongs to the victim, and the attacker manufactures a legitimate-looking
claim on it, because the routes by which an upstream decides what a customer may announce are softer than they
look.

Becoming a transit in the path. The cleanest version is consent that does not cover what is done with it. The
attacker sells transit to the victim, or to one of the victim's networks, and so genuinely carries the victim's
routes as a customer. Carriage was agreed; being the preferred path everywhere, and reading the traffic that
follows, was not. The origin stays the victim's and the AS_PATH is valid, which is what keeps the whole thing
inside the rules.

Authorisation at the upstream. To accept a prefix from a customer, an upstream wants evidence the customer may
announce it, and that evidence is weakly checked. A Letter of Authorisation, the document a provider takes as
proof, is rarely verified against who actually holds the space, so a forged, stale, or over-broad LOA can
enrol the victim's prefix into the set the attacker is permitted to announce. Where the filter is generated
from the IRR instead, the attacker pads an `as-set`, or registers a `route` object for the victim's prefix
under their own maintainer in a registry that does not check entitlement, and the automation authorises them
without a human ever looking.

Keeping the origin valid. A signed prefix forces a choice about how the route is announced. RPKI Route Origin
Validation checks only the last AS in the path against the ROA, so the route still has to carry the victim's
ASN as its origin to read `valid` downstream. Originating it from the attacker's own ASN would fail as
`invalid` wherever validation is enforced, which is the false-origin chain, not this one. Where the attacker
genuinely carries the victim as a customer the path already ends at the victim and nothing is fabricated. Where
it does not, presenting the victim as origin behind the attacker's own ASN means fabricating the AS_PATH: a
claim to be the victim's transit that no session actually backs. The protocol does not check that claim, which
is the only reason a router can emit it at all, so the forged path is announced over the attacker's genuine
upstream session and carried onward like any other. It passes ROV, because ROV never looks past the origin.
What it does not survive is a check against the real relationships, which is precisely the gap ASPA was written
to close: a network that has signed an ASPA object naming its real providers lets a validating core reject the
attacker as an upstream it never authorised. This is a forged path that rides a real adjacency, not a synthetic
route conjured from nowhere.

Authorisation that was never withdrawn. A relationship that has ended often leaves its filters and LOAs
standing. A former customer can keep announcing a prefix it no longer has any right to, simply because nobody
tore the permission down.

The common thread is that an upstream's belief in a customer's entitlement rests on documents and registry
data, not on a check against the address space's real holder. That gap is the right to announce, and once it
exists the rest is selection policy.

## A relationship that already wins

The lever is local preference, the first tiebreak in BGP best-path selection, set by the receiving AS and
weighed ahead of AS_PATH length, origin type and the rest. Operators commonly rank customer-learned routes
above peer-learned above provider-learned, because a customer route is the one they are paid to carry. So a
route entering an upstream through a customer relationship can beat a shorter, more legitimate route learned
from a peer, on preference alone.

This is a default, not a law. The ranking is configurable and often overridden per prefix, traffic-engineering
communities can be capped or ignored, and preference only ever decides among the routes an upstream has already
accepted. A route that its filters, its max-prefix limit, or RPKI validation refuse never reaches the
comparison, however preferred it would have been: validity gates before preference applies. The customer
session is the safe bet to win, not a guarantee of winning.

The position is therefore a legitimate relationship that already carries weight: a customer of an ISP, the
strongest, since customer routes sit at the top of that ranking, or a peer at an exchange, or a downstream of a
regional transit provider. None of it calls for deception. The relationship is contractually valid, and that
is exactly what makes it useful.

There is a bottleneck, and it is not the preference. A careful upstream will not let a customer originate a
prefix that is already globally visible on a clean path without a verified allocation or an explicit override
on the account, so the play does nothing against a provider that checks. The structural requirement is an
upstream whose customer filters are built by automation from registry data it does not verify, the
lazy-synchronisation case the acquisition above turns on. Finding that upstream is the real work; the local
preference is free once the announcement is accepted.

## Reading the selection policy

Local preference is set inside the receiving AS and is not visible from outside, so the attacker reads it
rather than queries it. Three readings usually suffice.

The norm. Customer over peer over provider, and local preference over path length, is near-universal, so a
customer session is a safe default bet to win.

The published knobs. Many transit providers document action communities that let a customer tune how their
routes are treated, including communities that raise or lower local preference or shape onward propagation.
These are public, and they say plainly which value wins.

The observed behaviour. Where the policy is undocumented, the collectors reveal it: a route that wins despite a
longer AS_PATH can only be winning on local preference, so comparing what actually propagates against the path
lengths backs out the ordering without asking anyone.

## The announcement

Nothing about the announcement is fraudulent. The prefix is one the right acquired above covers, and it is
announced over the relationship that already carries preference. The craft is
in the attributes: ride the customer session for its default high local preference, and, where the upstream
publishes the knobs, attach the community that raises it further, while avoiding any prepending or
de-preferencing community that would hand the choice back to the legitimate path. On FRR, against an upstream
at `198.51.100.1`:

```
route-map TO-UPSTREAM permit 10
 set community 64509:120 additive    # the upstream's published "raise local preference" community

router bgp 64511
 address-family ipv4 unicast
  neighbor 198.51.100.1 route-map TO-UPSTREAM out
```

Even without the community, a customer-learned route already arrives at the upstream's highest local preference
by default; the community is an amplifier, not the mechanism. The upstream then selects the attacker's route as
best across its cone, not because it is shorter or more specific, but because policy says it is preferred.

That snippet is the genuine-transit case: the route arrives from the victim and only its outbound attributes
are set. Where the attacker is not actually carrying the victim, the prefix has to be put into the local table
first, a static route and a `network` statement as in the other chains, before the outbound route-map has
anything to act on, and the AS_PATH has to be crafted so the victim's ASN stays at the origin and the route
still validates. That fabrication, not the community, is the load-bearing and the detectable part, and it is
not a prepend: prepending lengthens the near side of the path and leaves the origin unchanged.

## The sequence as performed

1. Reach the router. `vtysh` on the attacker's own kit; the session is held by contract, not stolen.
2. Check the ground. `show ip bgp summary` for the upstream session, and `show ip bgp 203.0.113.0/24` to see
   which path is currently selected for the prefix and the AS_PATH it carries, so the gain is measurable.
3. Make the change. `configure terminal`. If the route is already learned from the victim, only the route-map
   and its outbound `route-map ... out` on the upstream are needed; if it is being injected, add the static
   route and `network` statement first so the router has a path to evaluate, and craft the AS_PATH to keep the
   victim's ASN at the origin. Then `end` and `write memory`.
4. Push it. `clear bgp ipv4 unicast 198.51.100.1 soft out`. As with any outbound policy change, the new
   attributes do not reach an established session until the session is refreshed.
5. Confirm and observe. `show ip bgp neighbor 198.51.100.1 advertised-routes` confirms the crafted route is
   going out; the upstream's looking glass, and the public collectors, show its cone now preferring the
   attacker's path. Traffic shifts onto it while the legitimate path stays up.

## Silent redirection

Traffic moves predictably and quietly. The flow follows the policy-preferred path, often bypassing the transit
it was meant to take, and frequently in large volume where the winning upstream is well-connected. The
legitimate path still exists the whole time: no outage, no flapping, nothing that reads as broken. Because that
path remains, it doubles as the onward route, so the redirected traffic can be forwarded to the real
destination after it is read, the same interception-for-free that a route leak gives.

## Why it is hard to detect

Everything is technically correct. The origin is valid, the prefix is authorised, and the attributes are
within policy, so monitoring tuned to find bad routes sees nothing to flag. The argument that something is
wrong is not technical but contractual: "you are abusing customer preference" against "we are using the service
as it was sold". Resolution is slow and political, and it runs on relationships rather than packets.

## What closes it

Little of this yields to validation, because nothing here is invalid. The counters are hygiene and policy:
verifying a Letter of Authorisation against RPKI or the real holder rather than taking it on trust, building
customer filters from RPKI-checked registry data, tearing authorisation down when a relationship ends, capping
the local preference a customer may set, rate-limiting traffic-engineering communities from sources that have
not earned them, and watching for sudden preference shifts that move large volumes. ASPA closes the structural
gap directly: by validating an AS_PATH against the provider relationships a network has signed, it lets a core
reject an attacker presenting itself as an unauthorised intermediate transit, however much local preference
the customer session carries. The standing lesson sits underneath all of them. BGP security is not only about validation, policy is part of the attack surface, and a
control-plane attack can be fully compliant with the protocol. If policy decides routes, policy can be
weaponised.

## Related

- [BGP hijacking & route leaks](../../../in/network/roots/ip/bgp-hijacking.md): general IPv4 context
- [IPv4 prefix hijacking](../../../in/network/roots/bgp/prefix-hijack.md): specific mechanics
