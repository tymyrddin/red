# Route legitimacy subversion and long‑term positioning

Undermine the *trust fabric* of inter‑domain routing so that the attacker’s routes are treated as normal and legitimate, 
even when they are not. This is about shaping the routing environment itself.

## Phase 0 — Preconditions (this is why it takes a state)

This is not “hack a router”. This is play the system:
* Influence registries, operators, policy discussions
* Maintain operations over months or years
* Absorb reputational risk quietly

## Phase 1 — Legitimacy groundwork

Before any hijack, ensures the AS looks *boring*:
* Stable routing history
* No obvious leaks or flaps
* Clean IRR objects
* Plausible business relationships

Result: When this AS announces something odd later, people assume it is a mistake, not malice.

## Phase 2 — Registry and policy manipulation (pre‑attack)

This is where routing governance is nudged.

* Create or influence:
  * Route objects
  * Aut‑num policies
* Delay or complicate:
  * RPKI adoption for specific prefixes
* Encourage “flexible” routing policies downstream

No BGP UPDATEs yet. But the board is being set.

## Phase 3 — Controlled origin confusion (control‑plane attack)

Now the actual BGP attack begins with intermittent origin manipulation:

* Announce a prefix with:
  * A different origin AS
  * Plausible upstreams
* Alternate between:
  * Legitimate‑looking origins
  * Withdrawals

Effect:
* Route collectors see inconsistency
* Operators get used to seeing multiple origins
* Alerts become background noise

The anomaly becomes *normalised*.

## Phase 4 — Opportunistic prefix takeover

Once confusion exists, escalate carefully.

Time prefix hijacks during instability. Act:
* During maintenance windows
* During unrelated outages
* During global routing churn

Because everyone is already distracted and baselines are already polluted. The hijack blends in.

## Phase 5 — Trust erosion without collapse

This chain does not aim to:
* Break routing globally
* Cause mass outages

Instead it causes:
* Reduced confidence in routing data
* Disagreement between sources
* Operator fatigue

Result: Even correct alerts start getting ignored.

## Phase 6 — Strategic advantage

Now tehre are options:
* Easier future interception
* Easier selective blackholing
* Faster influence operations later

The real payload is future freedom of action.

## Phase 7 — Persistence through institutional memory loss

People change jobs. Tickets get closed. Mailing lists move on. What remains:
* Dirty baselines
* Conflicting historical data
* Shrugged‑off anomalies

The attacker keeps their feet on the table.

## Why this is unambiguously nation‑state

* Requires years, not days
* Exploits governance, not software
* Depends on social trust in routing communities
* No direct profit motive

This is infrastructure geopolitics.

