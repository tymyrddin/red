# From casing to access

Attacking a target needs a position: a BGP session some upstream will accept announcements on. Acquiring such a position
varies more than the announcement that follows. From the slow and clean to the fast and stolen.

## Running an AS

The most legitimate position is a network of one's own: an Autonomous System with its own number, address
space, and at least one upstream to carry its routes. In practice this means becoming, or going through, a
Local Internet Registry.

Membership and numbers. An ASN is issued by a Regional Internet Registry (RIPE NCC, ARIN, APNIC, LACNIC,
AFRINIC), usually to an LIR or through a sponsoring LIR rather than to an individual directly. A 32-bit ASN is
plentiful and cheap, carrying an annual fee often in the low hundreds; 16-bit ASNs ran out years ago and now
change hands on a transfer market. The registry runs identity checks against a named organisation, so the
number is attributable from the moment it is issued.

### Address space 

IPv4 allocations from the registries are exhausted, so a usable block tends to come through the
transfer market via a broker, at a per-address price that moves with demand, and the transfer is recorded by
the registry. IPv6 is allocated freely and at little cost, though much of the older internet still treats IPv4
reachability as the thing that counts.

### Upstream and objects 

A transit provider or an exchange carries the announcements. A provider takes a Letter of
Authorisation for the prefixes, then builds a prefix filter from the customer's IRR objects, so the `route`,
`route6` and `as-set` objects are registered under a maintainer before anything propagates. Publishing a ROA
aligns the origin with RPKI. The session itself is plain eBGP, commonly run from a router or a small VM running
software such as BIRD or FRR.

### Filters are not continuous

Upstream routers regenerate their IRR-derived prefix-lists on discrete
schedules, often every two to twelve hours rather than on change, and `route` objects mirror between registries
on a similar lag. That latency is part of what the position is worth: a transient `route` object registered
before an upstream's sync window locks the filter open, then withdrawn before the next mirror cycle, leaves a
narrower permanent trail than a standing registration would.

### Frictions

Lead time runs to weeks once contracts, allocations and object registration are counted. 
A freshly issued ASN with no history tends to draw tighter filters and closer attention than an aged one, which
is why dormant ASNs with clean records carry a premium on the transfer market. The whole arrangement is named:
registry record, LIR membership and transit contract each carry an organisation behind them.

## The address lease market

Between running a network and signing a carrier contract sits a large middle ground that skips the registries
almost entirely. IP lease brokers and lower-tier commercial hosts rent address space and routing rather than
sell it: a small sub-allocated block, often a `/24`, that is already routed inside the lessor's infrastructure,
or a slice of an existing customer BGP session.

The appeal is speed and inheritance. There is no RIR identity check and no weeks of allocation paperwork, and
the rented block tends to arrive carrying the lessor's existing reputation and policy weight, the standing of
an established downstream business rather than a freshly minted ASN. The trade is dependence: the position
lives inside someone else's allocation and routing, visible to them and revocable by them, and the lease itself
is a commercial record that ties the renter to the space.

## Buying transit from a chosen upstream

A narrower version is a customer session on a particular upstream rather than a general one. The mechanics are
the same, a contract, a Letter of Authorisation, and a filter generated from the customer's `as-set`, but the
choice of provider changes what the position is worth. A customer-learned route is commonly set above peer- and
provider-learned routes in local preference, and local preference is weighed before path length, so a route
entering through a customer link can be preferred over a shorter one learned elsewhere.

The provider's own habits decide how much that position actually permits: whether it drops RPKI-invalids or
merely logs them, and how tightly it generates the customer filter. Because that filter is built from an
`as-set`, a loosely maintained `as-set` lets through more prefixes than the customer genuinely announces.

The other half of that filter is the maximum-prefix limit. A customer session carries a hard cap on how many
prefixes the upstream will accept, and a border router tears the session down the moment an announcement pushes
the count past it. A customer position is worth only as much as the headroom left in that limit: a leak or a
burst of more-specifics that overruns the cap drops the session rather than propagating.

## Joining an internet exchange

An Internet Exchange Point is a shared fabric where many networks meet. Membership means an application to the
exchange, a port fee, and a physical presence in the relevant facility, whether a rack of one's own or a port
rented through a reseller offering remote peering. Once connected, sessions are either bilateral, arranged one
operator at a time, or established through the exchange's route servers, which usually apply RPKI and IRR
filtering uniformly while bilateral arrangements vary by operator.

Membership is public. An exchange presence is listed in PeeringDB alongside the facilities and ASNs involved,
so the position announces itself to anyone who looks. The appeal is reach: one port can sit adjacent to many
networks at once.

## Remote peering and tunnelling

Physical presence at an exchange or carrier hotel is not the only way to hold a position inside one. Multi-hop
eBGP lets the session run over the public internet rather than a directly attached link: a lightweight GRE or
WireGuard tunnel to a cooperative or compromised router inside the target city or facility, with the eBGP
session fired through the tunnel.

This decouples where the operator sits from where the announcement appears. An authoritative footprint can be
dropped into a European or Asian exchange while the operator works from another continent, which keeps the
transport path away from local physical monitoring even where the routing position looks native.

## Borrowing a lab or research session

Some academic testbeds, research networks and teaching environments hand out real BGP sessions that announce
into the live table under light oversight. They are cheap and quick to obtain and attract little scrutiny,
though reach is usually limited and edge filtering can be strict. The PEERING testbed is the best known of the
academic ones, giving researchers controlled origination from real ASNs and prefixes.

## Taking a credential

Where a position is not bought, an existing one can be taken. The useful targets are administrative rather than
the routers themselves: an RIR portal account that can issue or alter ROAs, an IRR maintainer (the `mntner`
object) that governs `route` and `as-set` entries, an exchange portal, or a network operator's own management
plane. Control of the right account can make a forged announcement validate, by issuing a ROA for it or
registering a matching route object, without ever touching the victim's routers. Maintainer authentication has
historically been weak in places, and credential reuse and phishing reach much of the rest.

The approach is fast and cheap and stays deniable until logs are read, though it is plainly an intrusion, and
any edit leaves a record in someone else's system that outlasts the announcement.

## Already in position

The cheapest position is one already in hand. An operator that already runs a network, with a customer
relationship, an exchange presence, or a transit footprint in a useful place, originates from it at no extra
cost and with little that needs explaining, since the session is already part of normal business. A fair amount
of the value of reconnaissance is in recognising that the means is already held rather than waiting to be
acquired.

The cover such a position gives is plausibility. An unexpected announcement from an established footprint reads
as a fat-finger leak or a misconfiguration as readily as anything deliberate, and because legitimate networks
leak routes by accident routinely, the usual first response is a filtering tweak or an email asking for a fix
rather than isolation or a legal escalation.
