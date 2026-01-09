# Strategic traffic interception via stealthy prefix hijack

Silently observe traffic flows to or from a target organisation, sector, or country without causing outages and 
without triggering incident response alarms. This is intelligence collection, not vandalism.

## Phase 0 — Preconditions (why this works at all)

Before anything happens, several truths already exist:

* Large parts of the Internet still:
  * Do not enforce RPKI
  * Prefer longest‑prefix match over everything else
  * Trust customers more than they should
* Routing security is unevenly deployed
* Operators are trained to fix outages, not subtle interception

This chain can exploit *normal routing behaviour*.

## Phase 1 — Gain access to an announcing position

This is not hacking routers at random. Typical options:
* A small regional ISP
* A hosting provider with its own ASN
* A transit customer with BGP announce rights

How access can be obtained:
* Intelligence partnership
* Regulatory leverage
* Quiet acquisition
* Long‑term compromise of NOC systems

The key requirement: The attacker can legitimately send BGP `UPDATE`s to at least one upstream.

## Phase 2 — Target and prefix selection

Do homework. A lot of it.

### Selection criteria

* Prefixes that:
  * Are routable globally
  * Have incomplete or inconsistent RPKI coverage
  * Are not under constant scrutiny (banks are noisy, NGOs are quieter)
* Targets with:
  * Predictable traffic patterns
  * Valuable metadata (who talks to whom, when, how often)

### Intelligence gathering

* Passive BGP monitoring (RIS, route collectors)
* Long‑term baseline:
  * Normal AS_PATH length
  * Typical upstreams
  * Time‑of‑day stability

Nothing changes yet. Patience.

## Phase 3 — The BGP control‑plane attack (the core move)

This is where the actual attack happens. More‑specific, a prefix hijack. Example:

* Legitimate origin announces `203.0.113.0/22`
* Attacker announces `203.0.113.0/24`

No exploits. No floods. Just mathematics.

### UPDATE characteristics

* `AS_PATH` looks boring; `NEXT_HOP` is reachable; Announcement is gradual, stable, non‑flapping.

Avoid:
* Sudden global dominance
* Weird paths
* Breaking reachability

## Phase 4 — Traffic interception, not blackholing

This is the crucial difference between amateurs and skilled hackers.

- What *does not* happen: Traffic is not dropped, services do not go offline, users do not complain
- What *does* happen: Traffic is received by our `AS`, logged, mirrored, or analysed, and forwarded to the legitimate destination.

From the outside: Everything works, latency increase is marginal, traceroutes look “odd but plausible”.

Operators shrug and move on.

## Phase 5 — Persistence through restraint

Let us not get greedy.

Persistence techniques:
* Interception windows: Hours or days, not months
* Prefix rotation: Different /24s over time
* Scheduled withdrawals: Before anyone escalates

This avoids:
* Route‑leak accusations
* Social media outrage
* Emergency mailing list threads

## Detection (why defenders usually miss it)

Detection requires correlation, not alerts.

Defenders would need:
* Global BGP visibility
* RPKI validation *and* enforcement
* Historical comparison
* Awareness that interception is even a thing

What usually happens instead:
* “No outage observed”
* “Paths look valid”
* Ticket closed

## Strategic value

* Metadata intelligence:
  * Relationships
  * Timing
  * Volume
* Pre‑crisis mapping: Who depends on whom
* Attribution remains murky

There is no ransomware note. There is no splash. There is no glory. Just files quietly filling up.

## Why this is a textbook nation‑state chain 

* Long‑term planning
* Minimal operational noise
* No immediate financial payoff
* Exploits governance gaps, not software bugs

Criminals want chaos. States want continuity with visibility.

* The chain is entirely driven by:
  * BGP UPDATE messages
  * Path selection logic
* No need for packet‑level fakery
* Clean demonstration of:
  * Longest‑prefix match
  * Policy over security
  * Why “working Internet” ≠ “secure Internet”

Note: A *single* upstream enforcing RPKI breaks the chain
