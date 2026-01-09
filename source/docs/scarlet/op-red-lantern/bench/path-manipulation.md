# Path manipulation for selective degradation and coercion

Subtly degrade connectivity for a specific target without breaking it, in order to:

* Influence behaviour
* Apply pressure
* Signal capability without escalation

This is about leverage, not intelligence harvesting.

## Phase 0 — Preconditions (the quiet setup)

Have access to an ASN with:
  * Multiple upstreams
  * Legitimate transit relationships
* Political or economic interest in the target’s connectivity
* Time to experiment slowly

The Internet’s default assumption helps:  Routing instability is usually blamed on “the network”.

## Phase 1 — Target dependency mapping

Before touching BGP, map dependency paths. What to identify:
* Which upstreams the target relies on most
* Which IXPs and transits are critical
* Which routes are latency‑sensitive (VPNs, VoIP, control links)

How?
* Passive BGP observation
* Historic traceroutes
* Prior outages (Internet never forgets its own scars)

No packets are altered yet.

## Phase 2 — Controlled AS_PATH manipulation (control‑plane attack)

This is the first explicit BGP control‑plane move.

Technique: Artificial AS_PATH shortening or lengthening.
* Re‑announce existing prefixes
* Adjust AS_PATH attributes to:
  * Attract traffic from specific regions
  * Repel traffic from others

Examples:

* Shorter path for certain peers → traffic pulled in
* Longer path advertised selectively → traffic pushed away

No hijack yet. Still “legitimate”.

## Phase 3 — Targeted prefix de‑aggregation

Now the attack sharpens. Select more‑specific announcements instead of hijacking everything:
* Only critical sub‑prefixes are announced
* Only to selected peers or IXPs

Effect:
* Some paths reroute
* Others remain unchanged
* The Internet fractures quietly

From the target’s perspective:
* “Some users complain”
* “Only from certain regions”
* “Intermittent”

Perfect ambiguity.

## Phase 4 — Induced instability without outage

Avoid:
* Route flapping
* Global instability
* Blackholing

Instead:
* Mild packet loss
* Increased jitter
* Unpredictable path changes

This is achieved by:
* Timed UPDATEs
* Temporary withdrawals
* Preference oscillation

Still pure control‑plane manipulation.

## Phase 5 — Attribution fog

This is where nation‑states shine.

Why attribution fails:
* Routes are technically valid
* No obvious hijack signature
* Behaviour resembles misconfiguration or congestion

Operators argue:
* Upstream blames downstream
* Downstream blames transit
* Everyone blames “the Internet”

The attacker stays silent.

## Phase 6 — Strategic signalling

This chain often runs alongside diplomacy. The target notices:
* Services feel “fragile”
* Reliability degrades at inconvenient moments
* Problems disappear just as mysteriously

Message received: “We can touch your connectivity without breaking it.” No communiqué required.

## Phase 7 — Exit and reset

Once the signal is sent:
* Routes return to baseline
* `AS_PATH`s normalise
* Prefixes are withdrawn cleanly

No lasting damage. No incident report with teeth. Just unease.

## Why this is clearly a nation‑state chain

* Requires upstream cooperation or coercion
* Zero immediate financial gain
* Carefully calibrated impact
* Designed to remain below escalation thresholds

Criminals smash. States *nudge*.

This demonstrates:
* `AS_PATH` manipulation effects
* De‑aggregation impact
* Regional routing differences
* “Nothing is down, yet everything is worse”

All driven by:
* BGP UPDATEs
* Policy decisions
* Timing

No payloads. No malware. Just governance failure expressed in routing tables.


