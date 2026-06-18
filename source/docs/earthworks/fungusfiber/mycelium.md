# Operation Mycelium

Operation Mycelium is the slowest exercise against [FungusFiber Internet](entity.md), and the least like an
attack. It is not a move but a campaign, and its target is not a prefix but the trust around FungusFiber's
registry. Over years, Shadow6 makes an autonomous system boring and a Fungolian prefix look habitually
multi-origin, so that when an announcement finally comes it reads as a mistake and the alert reads as noise.
For most of its life Mycelium touches neither a packet nor a route. Its medium is the registries, the published
baselines, and the confidence [Fungolia](../fungolia.md)'s operators place in both, and it works on the layer
where people and tools decide what is worth investigating, not on the forwarding decision, which each router
still makes in the present tense by its own policy.

The author again is Shadow6, the Borogravian regency's cyber wing. The payload is not today's traffic but
tomorrow's freedom of action: every louder exercise, Toadstool and Blight among them, gets easier once the
ground has been prepared. It belongs to Shadow6 rather than to a smash-and-grab criminal precisely because it
takes years, the reach to nudge registries and policy talk, and the patience to carry quiet reputational risk
without flinching.

## Looking boring on purpose

The groundwork is to make an AS unremarkable. Shadow6 grows a stable routing history for it, no visible leaks
or flaps, clean registry objects, and plausible business relationships near FungusFiber, all toward one
effect: when this AS later announces something odd, the reflex is to read it as a mistake rather than malice.
A clean history can only be grown, not bought in a hurry, which is part of why the long game belongs to an
actor that can wait.

## Setting the board in the registries

The pre-attack theatre is the routing registries and RPKI. Shadow6 registers route objects and an `aut-num`
describing a believable import and export policy, builds an `as-set`, and holds it under a maintainer that
ages into credibility. The softness exploited is that several registries are not authoritative and do not
check that the registrant actually holds the resource, so an object asserting a Fungolian prefix can simply be
entered:

```
route:     203.0.113.0/24
origin:    AS64511
mnt-by:    MAINT-AS64511
source:    RADB

aut-num:   AS64511
import:    from AS64509 accept ANY
export:    to AS64509 announce AS64511
mnt-by:    MAINT-AS64511
source:    RADB
```

Alongside the objects, Shadow6 keeps the Fungolian spaces meant for later use unsigned or loosely signed, RPKI
adoption for those prefixes quietly stalled in committee, the kind of stalling Fungolia's consensus politics
makes easy. No BGP UPDATEs are sent at this stage. The board is being set.

How far the board reaches is easy to overstate. Registry data is advisory rather than authoritative, acted on
only by the networks that still build filters from it without an RPKI cross-check; many ignore it, and where
validation is enforced the registry narrative counts for nothing at origin validation. So the groundwork opens
uneven local gaps rather than a coordinated global shift, and its worth is concentrated exactly where signing
and enforcement are already thin, a surface that narrows as RPKI adoption spreads.

## Normalising the anomaly

The first control-plane move is small and deliberately inconclusive. Shadow6 announces the prefix from an
alternate but plausible origin with believable upstreams, then withdraws it, on a slow and irregular cycle.
The collectors record the inconsistency, FungusFiber's operators grow used to seeing the prefix under more
than one origin, and the multiple-origin alerts blur into background noise. The effect is to widen the
prefix's recorded baseline until its normal already includes the kind of anomaly Shadow6 will later need.

The layer this moves is detection and response, not acceptance. A router still drops an invalid route however
familiar the multiple origins have become, so what widens is the human threshold for escalation, the tolerance
of the statistical detectors that learn a baseline, and the confidence placed in the tooling. Even that
softening is a bet rather than a certainty: detection increasingly correlates independent sources, RPKI state,
registry consistency, the relationship graph, rather than trusting a single learned baseline, and a
manufactured multiple-origin history that quiets one detector tends to surface as a mismatch in another. The
pollution buys hesitation and delay, not blindness.

## Taking the prefix when no one is looking

Once the baseline is polluted, the real takeover is timed to instability rather than announced into calm,
during a maintenance window, an unrelated outage, or a spell of churn. Attention is elsewhere and the baseline
is already dirty, so the move blends into conditions that are noisy on their own. The churn buys slower human
response, not easier acceptance, since convergence and policy run per router regardless of who is watching. The
takeover still has to survive present-tense policy at every hop, so it rests on the same unsigned or
unenforced condition the other exercises turn on; the years of groundwork multiply that gap rather than
replacing it, and without a prefix actually announceable past the filters, none of the narrative reaches a
forwarding table.

## What it buys, and what closes it

The yield is strategic rather than immediate: easier interception later, easier selective degradation, faster
work when Shadow6 wants it. The real payload is future freedom of action, and it persists through institutional
memory loss. People change jobs, tickets are closed, and what remains is dirty baselines, conflicting history,
and anomalies everyone has learned to shrug at.

What closes it is mostly institutional, which is why it is hard, and one technical fact sets the ceiling on the
rest: the routing system does not really remember. It evaluates, filters and drops in the present tense by
local policy, so where RPKI and validation are deployed the registry objects and the polluted baseline count
for nothing at the moment of decision, and the collectors that recorded all that inconsistency feed dashboards,
not forwarding tables. 

The defender's-side reconstruction can be found in the blue notes on
[inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/): authoritative registries that
check entitlement, RPKI used as the source of truth with prefixes signed under tight max lengths, and
detectors that treat a sustained low-grade anomaly as signal rather than noise. Underneath all of it sits the
defence Mycelium attacks most directly, the [posture](https://blue.tymyrddin.dev/docs/counter/inter-domain/posture/)
of continuity and a scepticism that outlasts staff turnover.
