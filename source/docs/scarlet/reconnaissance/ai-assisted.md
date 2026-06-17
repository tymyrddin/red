# AI in the loop (2026)

Machine help has not changed the physics of routing. It has compressed the analyst's time, which is enough to
change which operations are worth running. This page is the 2026 layer over the rest of the section, and the
standing catch is that the same models defenders run are the ones an outsider is trying to stay under.

## What the detectors actually compute

Detection has gone statistical, and knowing features is usually knowing blind spots. The public
classifiers, GRIP from Georgia Tech, ARTEMIS from FORTH, Cloudflare Radar, and the bgp.tools feeds, mostly
score a small set of signals:

![Each signal paired with its evasion](/_static/images/07-detector-signals.png)

A move that throws none of these, a more-specific within an authorised max length, a stable non-flapping
announcement, an origin that is `not-found` rather than `invalid`, sits in the gap by construction. Profiling
which signals a given detector weights is the modern form of casing.

More of these run as public dashboards: [Qrator.Radar](https://radar.qrator.net/) correlates incidents, paths
and policy changes across hundreds of sessions, and [RoutePulse](https://www.goline.ch/routepulse/) exposes
MOAS, hijacks, route leaks, ASPA-invalids and ML correlations. Being public, they read as well for profiling
what a detector sees as for the detection itself.

## Pipelines instead of vigils

The same `pybgpstream` that pulls history, re-run over the latest window on a schedule, becomes a standing
watch, so baselining and window-spotting stop being manual:

```python
from pybgpstream import BGPStream

stream = BGPStream(
    from_time="2026-06-13 08:00:00",
    until_time="2026-06-13 09:00:00",
    collectors=["route-views2", "rrc00"],
    record_type="updates",
    filter="prefix more 203.0.113.0/24",
)
for rec in stream.records():
    for elem in rec:
        if elem.type not in ("A", "R"):   # announcements and RIB entries carry a path
            continue
        path = elem.fields["as-path"].split()
        print(rec.time, elem.fields["prefix"], path[-1], len(path))
```

Wrapped in a model that knows the prefix's normal, this surfaces a deviation, or an opportune window, as each
window lands rather than on a manual pass. The model need not be clever here. It needs to be patient, which it
is for free.

## Synthesis and topology

Language models fold WHOIS, IRR, PeeringDB, AS-rank and collector history into a ranked candidate list far
faster than a person reads them, which is target selection done in an afternoon rather than a fortnight.
[BEAR: BGP Event Analysis and Reporting](https://papers.cool/arxiv/2506.04514) is the published form of the
same idea pointed at a single event, using an LLM to turn it into an analyst-readable report: what the MOAS
was, which ASes, the historical context, the likely causes, and where to look next.
Graph and embedding models over the AS adjacency graph surface dependency chokepoints, a node whose
misbehaviour would read as congestion, at a scale no analyst would attempt by hand. Neither is a new
capability. Both are cheaper ones.

## The catch

Automated recon leaves its own prints: query cadence, account and API usage, and the tell-tale breadth of a
sweep that no human would run. And the asymmetry favours the defender, who points the same classifiers and the
same baselining at the same stream with far more context about their own prefixes than an outsider has.
