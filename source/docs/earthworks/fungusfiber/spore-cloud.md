# Operation Spore Cloud

Operation Spore Cloud is the same registry hit as Toadstool, run by a machine. The hand is Deep Vector, the
cyber arm the red files number APT-99, a modernising faction of the Agatean court that has decided the Circle
Sea is worth a model's attention. What took Shadow6 a room of specialists, Deep Vector compresses into an
afternoon: it reads FungusFiber's public footprint, writes the lure, finds the way up, and times the hijack,
none of it audited by hand. The end is not destruction but interception, reading the frontier's traffic and
passing it on, so nothing visibly breaks.

## Machine reconnaissance

Deep Vector folds FungusFiber's public footprint into a ranked list of soft spots without sending a packet:
the support portal and its password habits, a network-status blog's incidental detail, the registry
allocations, the role profiles of engineers worth phishing, and the staging nodes quietly bridged into the
production core. What a human analyst pieces together over days, the model assembles in minutes, because the
work is reading and connecting public information at speed, not breaking in.

## The perfect lure

The same model writes the way in. Given a scrape of a FungusFiber engineer's public writing for tone and
jargon, it drafts an urgent internal note from a network manager about BGP route flapping, pointing at a
configuration review on an internal portal, in the pressured office English of a real Fungolian operator. The
badly written giveaway phish is gone; what lands is clean enough to pass for a genuine message.

## Escalation at machine speed

On the foothold the lure buys, the model reads the local configuration and names the fastest way up. A finding
like a `support` account permitted to run `tcpdump` as root resolves in seconds to a known escape into a root
shell. Hours of manual searching collapse into a prompt and an answer, which is the whole advantage: the
timeline shortens until it is shorter than the defender's.

## The interception

From a position on FungusFiber's backbone, Deep Vector announces a more-specific of a target block beyond the
provider, `192.0.2.0/25` carved from a `/24` held elsewhere, and longest-prefix match hands it that range. BGP
only draws the traffic in, though. Copying it is a separate forwarding-plane tap Deep Vector supplies, not
something the protocol does, and the aim of Spore Cloud is to read what arrives and pass it on, so the hijack
stays transparent.

That passing-on is the hard part. Captured traffic has to reach its real destination by a path that does not
loop back into the hijack, so Deep Vector keeps one egress clean by poisoning the announcement, listing the
return-path AS in the AS_PATH so that AS rejects the more-specific on loop detection and keeps routing to the
genuine origin:

```
ip route 192.0.2.0 255.255.255.128 198.51.100.9

route-map MITM permit 10
 set as-path prepend 64509

router bgp 64500
 address-family ipv4 unicast
  network 192.0.2.0 mask 255.255.255.128
  neighbor 198.51.100.1 route-map MITM out
```

The static route does double duty: it puts the more-specific in the table so the `network` statement
originates it, and it forwards captured packets toward the real origin through `198.51.100.9`, the upstream in
AS64509 that the poison made ignore the route. Inbound is drawn in by the more-specific; outbound rides the
clean path. The result is a man-in-the-middle on the toward-target direction, the traffic read on the way
through and delivered intact.

None of this is as clean as it sounds, and the model does not make it so. The poison keeps an egress only
where that AS's own route to the origin does not run back through FungusFiber, which is topology-dependent
rather than guaranteed. The return direction is computed independently by the far end and is rarely symmetric,
so Spore Cloud taps one side of a conversation, not both. And a single upstream on the path that enforces
origin validation drops the more-specific outright where the block is signed, which is the one move that ends
the whole exercise.

## The hidden aftermath

The yield is metadata and credentials: who FungusFiber's customers talk to, when, and the tokens and cookies
that ride the captured flows, taken in a window short enough to pass for a transient wobble. There is no ransom
note and no outage, which is exactly the point, and attribution stays murky. The model did not change the
physics of routing; it compressed the analyst's time, which is enough to put a sophisticated chain within reach
of a smaller team and to shorten the window in which anyone could react.

## Switching hats

The chain marks its own defences. The lure meets training and a reporting culture; the escalation meets least
privilege and patched tooling; the interception meets the inter-domain controls, a ROA with a tight max length
so there is no more-specific to carve, and an upstream that enforces validation so the forged route is dropped
before it spreads. The defender's-side reconstruction is in the blue notes on
[inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/).
