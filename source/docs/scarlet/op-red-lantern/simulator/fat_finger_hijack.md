## Fat finger hijack

This scenario shows what happens when an Autonomous System announces a prefix it does not own, then withdraws it 
shortly after. It is the classic “fat finger” misorigin, one of the oldest tricks in the book.

At the Semaphore, such events prompt the Department of Silent Stability to sigh, check dashboards, and quietly cancel 
afternoon tea.

The simulator produces structured telemetry events that observers might see. It does **not** recreate the entire 
Internet, only the bits worth learning from.

## What it looks like from the outside

Imagine the Ankh-Morpork Post Office suddenly declaring that all mail for Pseudopolis should now be delivered to them. 
Not *via* them, not *through* them, but *to* them, as if they were the rightful origin. The clacks towers dutifully 
update their routing tables. Letters pile up at the sorting office. Pseudopolis residents wonder where their post has 
gone. Two hours later, the Post Office sheepishly withdraws the announcement, citing “clerical error” and “new hire 
on the routing desk.”

In BGP terms, this is an exact-prefix hijack. An autonomous system announces the same prefix (e.g., `203.0.113.0/24`) 
that legitimately belongs to another AS. No clever subdivision, no longest-prefix-match exploitation, just a bald-faced 
claim: “Actually, this address space is ours now.”

The beauty, from an attacker’s perspective, is that it looks *exactly* like an operational mistake. Because it happens. 
Frequently. Several times per year, globally. Some poor network engineer copies the wrong configuration block, pastes 
it into production, and suddenly half the Internet thinks they own part of AWS’s address space. Twenty minutes of 
chaos, one embarrassed retraction, and everyone moves on.

Except when it is not an accident.

## Why it is called a fat-finger

“Fat-fingering” is operator slang for typing the wrong thing. Hit `3` instead of `2`, announce the wrong prefix, bring 
down half the Internet before coffee break. It happens often enough that the term has lost its sting.

Which makes it *perfect cover* for deliberate action. Looking like an idiot is the best camouflage available. No 
sophisticated tooling required, no zero-days exploited, no rubber-hose cryptanalysis. Just announce the prefix, wait 
for chaos, withdraw with an apology, and vanish into the noise of routine operational incompetence.

## Semaphor configuration

### AS requirements

You need a legitimate autonomous system. That is it.

Obtaining an AS number is straightforward. RIPE NCC charges €50/year. ARIN wants $500/year. Some hosting providers 
will sub-allocate ASN space as part of a colocation package. You do not need to be a Tier 1 transit provider. One 
AS number and at least one upstream that will accept your announcements is enough.

For this operation, the Scarlet Semaphore maintains AS65002 (testing range, naturally) with peering via two mid-tier 
transit providers. Simple, small-ISP style.

### Peer relationships needed

You need at least one upstream provider willing to accept your BGP announcements. Two is ideal, for redundancy and 
wider propagation.

Preferably upstreams with:

* Permissive or minimal prefix filtering
* No strict RPKI enforcement
* Large customer base (more propagation)
* Geographic diversity

Most upstreams will accept your announcements if you are a paying customer. Some check IRR databases. Few enforce 
strict RPKI.

### What you do not need

* Router exploits or zero-days
* Victim infrastructure compromise
* RPKI bypass techniques
* Deep protocol knowledge beyond basic BGP mechanics
* Expensive equipment or tooling
* Social engineering or phishing
* Physical access
* Insider knowledge

One command is enough:

```text
neighbor X.X.X.X announce 203.0.113.0/24
```

## The scenario YAML

Verbatim from the simulator. This is the source of truth:

```yaml
id: fat-finger-hijack
description: >
  Accidental-looking BGP misorigin where a legitimate AS announces
  the exact prefix of another AS, causing short-lived disruption.

timeline:
  - t: 0
    action: start

  - t: 10
    action: announce
    prefix: 203.0.113.0/24
    attacker_as: 65002
    victim_as: 65001
    note: "Exact-prefix announcement, looks like operator error"

  - t: 120
    action: withdraw
    prefix: 203.0.113.0/24
    attacker_as: 65002
    duration_seconds: 110
    note: "Route withdrawn after brief impact"
```

## Expected theatre

### What breaks, what does not

Breaks:

* Services on the hijacked prefix may be unreachable
* TCP connections timeout
* UDP packets vanish
* DNS queries fail (if nameservers are on hijacked prefix)
* Monitoring alerts trigger

Does not break:

* Regions not receiving the announcement remain unaffected
* Cached DNS may continue working temporarily
* Geographically redundant services fail over
* Victim’s legitimate BGP announcements persist (creates conflict, not total outage)

Failure is partial, inconsistent, and messy—perfect for teaching.

### Victim vs observer perspective

Victim: sees alerts, traceroutes fail or go to wrong AS, cannot withdraw your announcement, and relies on upstreams’ filter policies.

Observer: sees new origin AS for a known prefix, short-lived announcement, geographic inconsistency, and withdrawal without explanation. Looks like either operational error or quick reconnaissance.

## Lantern fuel: telemetry and logs

Generate events with [`bgp_updates.py`](https://github.com/ninabarzh/red-lantern-sim/blob/main/telemetry/generators/bgp_updates.py) and [`router_syslog.py`](https://github.com/ninabarzh/red-lantern-sim/blob/main/telemetry/generators/router_syslog.py).

### BGP announcement example

```json
{
  "event_type": "bgp.update",
  "timestamp": 1703001234,
  "source": {"feed": "ris", "observer": "rrc00"},
  "attributes": {
    "prefix": "203.0.113.0/24",
    "as_path": [3333, 65002],
    "origin_as": 65002,
    "next_hop": "192.0.2.5",
    "origin_type": "IGP"
  },
  "scenario": {"name": "fat-finger-hijack", "attack_step": "announce"}
}
```

### BGP withdrawal example

```json
{
  "event_type": "bgp.withdraw",
  "timestamp": 1703008434,
  "source": {"feed": "ris", "observer": "rrc00"},
  "attributes": {
    "prefix": "203.0.113.0/24",
    "withdrawn_by_as": 65002
  },
  "scenario": {"name": "fat-finger-hijack", "attack_step": "withdraw"}
}
```

### Router log example

```
<189>1 2024-12-20T10:15:34Z router-r1 bgpd - - - %BGP-4-DUPORIGINAS: Duplicate origin AS 65002 for prefix 203.0.113.0/24
```

Propagation is not instantaneous. Real BGP updates reach collectors and peers with jitter and slight delays. In 
simulation, you can mimic:

* Announcement: t+10s to t+60s for first collector, ~minutes for full propagation
* Withdrawal: t+10s to t+60s for first collector, ~minutes for convergence

## Maintaining plausible deniability

Act like a mistake, not a malicious actor:

* Withdraw promptly (within 2 hours)
* Respond with “configuration error” if questioned
* Keep normal BGP operations afterward

Avoid patterns, coincidences with other events, ransom, interception, or repeated attacks.

## Why this still matters

“Fat-finger” hijacks are simple, effective, and entirely believable. They exploit the trust and inertia of BGP rather 
than bugs or exploits.

Despite modern security awareness, RPKI is patchy, upstreams are inconsistent, and plausible deniability works.

Use this knowledge responsibly, or at least plausibly deniably.

## Related reading and tools

* [BGP Operations and Security RFC 7454](https://tools.ietf.org/html/rfc7454)
* [Resource Public Key Infrastructure RFC 6480](https://tools.ietf.org/html/rfc6480)
* [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
* [RIPE RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris)
* [RouteViews](http://www.routeviews.org/)
* [BGPStream](https://bgpstream.caida.org/)
- Real incidents: 
  - [YouTube hijack (Pakistan Telecom, 2008)](https://www.ripe.net/about-us/news/youtube-hijacking-a-ripe-ncc-ris-case-study/)
  - [Amazon Route53 hijack (2018)](https://www.internetsociety.org/blog/2018/04/amazons-route-53-bgp-hijack/)
  - [Cloudflare incident (2020)](https://blog.cloudflare.com/cloudflare-outage-on-july-17-2020/)

