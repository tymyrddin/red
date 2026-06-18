# Operation Foxfire

In Operation Foxfire the routing move is not the headline; it is the enabler. Deep Vector degrades a handful of
high-visibility [Fungolia](../fungolia.md) services during a Circle Sea summit, timed to the news cycle, to
feed a story already running about the frontier ally's unreliability. The product is public doubt, not
downtime. The redirection lives entirely in the control plane and forges no packets; what is distinctive is the
timing and the company it keeps. Foxfire is the cold glow on the forest floor that leads a traveller off the
path: nothing is burning, and yet nobody arrives where they meant to.

The author is Deep Vector, the cyber arm the red files number APT-99, a modernising faction of the Agatean
court that pairs routing manipulation with an information campaign. Where Shadow6 nudges quietly during talks,
Deep Vector wants the disruption seen, and seen at the worst possible moment for Fungolia.

## A story already running

The anomaly needs a narrative to land in. An Agatean campaign about the frontier ally's fragility, friction
around the Circle Sea talks, and media framing of Fungolian mismanagement are the soil; without them, a
routing blip is just a blip. Deep Vector times the routing to amplify a story already in circulation rather
than to start one, which is also what lets it stay silent later and let others draw the conclusion.

## Targets chosen for visibility

The selection is about embarrassment, not volume. Services that are humiliating to lose for an hour while the
summit watches, the government portal, the emergency committee's coordination frontend, the national media
platform, are worth more than busy ones, and more again where they lean on a particular FungusFiber upstream
or exchange the dependency map has named. The aim is never a total outage. It is maximum embarrassment per
packet.

## Positioning

As in the other exercises, Deep Vector works from a position with announce reach over the Fungolian prefixes,
held or taken, the access from Spore Cloud serves, where the UPDATEs are believed and carried. Nothing here
needs a fresh router exploit, only standing.

## The move, timed to the moment

The toolkit is Blight's, fired into a window rather than spread over a season. Deep Vector applies a brief
more-specific, a selective prepend, or a raised MED to the target's prefixes only, toward certain regions
only, and only while the summit runs. Rather than blackhole, which would read as an outage, the traffic is
steered onto a congested or distant path so it degrades:

```
route-map TO-REGION permit 10
 set as-path prepend 64511 64511 64511

router bgp 64511
 address-family ipv4 unicast
  neighbor 198.51.100.10 route-map TO-REGION out
```

What users meet is slow pages, stuttering streams, and an intermittent "service unavailable"; what operators
see is no total loss, no clean hijack signature, and conflicting reports from different regions. Everything
stays technically valid, so it rides the same coverage and enforcement gaps as the other exercises, and a
prefix that is signed and enforced along its paths resists it. This is the inverse of Blight's cover-timing:
Blight hides inside churn, Foxfire fires into the spotlight, because being felt at the right moment is the
whole point. The window is the calendar's, the summit's opening session, not the routing table's.

The selectivity is approximate rather than surgical, though. BGP expresses region and service poorly unless
Deep Vector's position happens to align with the target's geography, so the effect tends to spill across paths
that were never meant to move. And the gap between degradation and outage is a brittle place to stand: anycast,
multi-CDN delivery and multi-homing absorb much regional steering, monitoring correlates latency and routing
shifts quickly, and automatic mitigation may reroute around the trouble before any narrative forms. The state
where it reads as unreliable rather than down is real but usually narrow, and easily reclassified as ordinary
congestion.

## Letting others tell the story

The other half is not technical. Agatean-aligned outlets report Fungolian technical failures, social platforms
amplify the complaints, and commentators question competence, much of it unprompted, because the narrative was
already running. Deep Vector says nothing, and the instability becomes proof of a story that predates it. The
coupling is looser than it looks, though. A routing event is not legible to the public directly; it reaches
people through a status page, an official statement, a journalist's summary, so the belief shift is produced by
how the disruption is explained rather than by the disruption itself. The real payload sits in the
institutional response layer, a different system from the routing, which is why Foxfire bites only where that
layer is already primed to read a failure as incompetence.

## Withdrawing before it sets

Before attribution can solidify, Deep Vector withdraws the routes, the live paths return to baseline, and the
monitoring graphs flatten. The post-incident account writes itself in the moment: a transient routing issue,
no evidence of an attack, root cause unclear. What the withdrawal buys, though, is time against a real-time
human response, not erasure. The event persists in the collector archives, RIPE RIS and RouteViews, in router
and CDN logs, and in the commercial monitors, fully reconstructable later, and a short anomalous burst can read
as more suspicious than a sustained one for lacking any routine operational story. So the deniability rests on
the pre-existing narrative and the ambiguity at the moment, not on the record being gone.

## What remains, and what closes it

What is left is public doubt, institutional embarrassment, and pressure on Fungolia at the table, with no
sanctions triggered and no red line crossed. Credibility is dented, and that lasts far longer than the anomaly
that dented it. The shape is a state's: synchronised with information operations, scoped to avoid escalation,
built for deniability, and aimed at human interpretation rather than at the protocol alone. The routing half
yields to the same defences as the other exercises, a ROA with a tight max length and an enforcing upstream
shorten the window and force a cleaner, more attributable signature, which is exactly what a deniable operation
cannot afford. The other half is not a routing problem. Once an anomaly is brief, partial and plausible, the
contest moves to explanation, and the counter is the unglamorous one of accounting for an incident clearly and
quickly enough that "transient issue" does not harden into "they cannot cope". The honest limit sits underneath
all of it: BGP can shift reachability and sometimes performance, but it does not move interpretation. The
routing anomaly is only an input to a perception system it does not control. The defender's-side reconstruction,
and the [posture](https://blue.tymyrddin.dev/docs/counter/inter-domain/posture/) that meets it, are in the blue
notes on [inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/).
