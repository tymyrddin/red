# Fat finger hijack

## Or The Misaddressed Lantern or The Accidental Beacon

Or how one wrong number brings down the entire postal system.

- Difficulty: easy
- Plausible deniability: Excellent  
- Detection likelihood: Low (without proper instrumentation)

## The Signal

### What it looks like from the outside

Imagine the Ankh-Morpork Post Office suddenly announcing that all mail for Pseudopolis should now be delivered to 
them instead. Not *via* them, not *through* them, but *to* them. As the rightful origin. The clacks towers dutifully 
update their routing tables. Letters pile up at the Ankh-Morpork sorting office. Pseudopolis residents wonder where 
their post has gone. And then, two hours later, the Post Office sheepishly withdraws the announcement with a memo 
about "clerical error" and "new hire on the routing desk."

In BGP terms, this is an exact-prefix hijack. An autonomous system announces the same prefix 
(say, `203.0.113.0/24`) that legitimately belongs to another AS. No clever subdivision, no longest-prefix-match 
exploitation, just a bald-faced claim: "Actually, this address space is ours now."

The beauty, from an attacker's perspective, is that it looks *exactly* like an operational mistake. Because it 
happens. Frequently. Several times per year, globally. Some poor network engineer copies the wrong configuration 
block, pastes it into production, and suddenly Netflix thinks they own part of AWS's address space. Twenty minutes 
of chaos, one embarrassed retraction, and everyone moves on.

Except when it's not an accident.

### Why it's called a fat-finger

"Fat-fingering" is operator slang for typing the wrong thing. Hit `3` instead of `2`, announce the wrong prefix, bring 
down half the internet before coffee break. It happens often enough that the term has lost its sting.

Which makes it *perfect cover* for deliberate action.

If you're going to hijack a prefix, looking like an idiot is the best camouflage available. No sophisticated 
tooling required, no zero-days exploited, no rubber-hose cryptanalysis. Just announce the prefix, wait for chaos, 
withdraw with an apology, and vanish into the noise of routine operational incompetence.

The term "fat-finger" implies clumsiness, not malice. It suggests someone who should be retrained, not investigated. 
And that's precisely why it works.

That said, in 2025, this still works. Which tells you everything you need to know about the state of BGP security.

## Semaphor configuration

### AS requirements

You need a legitimate autonomous system. That's it. That's the list.

Obtaining an AS number is not particularly difficult. RIPE NCC charges €50/year. ARIN wants $500/year. Some hosting 
providers will sub-allocate you ASN space as part of a colocation package. You don't need to be a Tier 1 transit 
provider. You don't need thousands of routes. You just need one AS number and at least one upstream that will accept 
your announcements.

For this operation, the Scarlet Semaphor maintains AS65002 (testing range, naturally) with peering via two 
mid-tier transit providers. Nothing fancy. The kind of setup a small regional ISP might have.

### Peer relationships needed

You need at least one upstream provider willing to accept your BGP announcements. Ideally two, for redundancy and 
wider propagation.

What you're looking for in an upstream

- Permissive prefix filtering (or none at all, depressingly common)
- No RPKI enforcement, or "invalid=log" rather than "invalid=drop"
- Large customer base (your poisoned routes reach more victims)
- Geographic diversity (routes propagate globally)

Most upstreams will accept your announcements if you're a paying customer. Some perform cursory checks against IRR 
databases. Very few enforce RPKI strictly. Fewer still validate that the prefixes you're announcing actually belong 
to you.

This is the trust model of the early internet, preserved in amber and still running production traffic in 2025.

### What you don't need

Let's be clear about what this attack does not require, because the absence of sophistication is the point.

You don't need:

- Router exploitation or zero-days
- Compromise of the victim's infrastructure
- RPKI bypass techniques (because RPKI enforcement is spotty at best)
- Deep protocol knowledge beyond basic BGP mechanics
- Expensive equipment or tooling
- Social engineering or phishing
- Physical access to anything
- Insider knowledge of the victim's network

You need one command: `neighbor X.X.X.X announce 203.0.113.0/24`

That's it. That's the attack.

The fact that this still works should keep network security professionals awake at night. It mostly doesn't, which 
is part of the problem.

## The Sequence

### 1. Preparation (t=-24h)

Identify target prefix. Check RPKI status. If the victim has a valid ROA, you'll have reduced propagation (strict RPKI enforcers will reject you). If they don't, you're golden.

Research victim's upstreams using [Hurricane Electric's BGP Toolkit](https://bgp.he.net/). Note who peers with whom. Plan your announcement timing for maximum impact, minimum attention (Friday afternoon, maintenance windows, major holidays).

### 2. Announcement (t=0)

Configure your router to announce the victim's prefix.

```
router bgp 65002
 neighbor 192.0.2.1 remote-as 64496
 network 203.0.113.0 mask 255.255.255.0
```

The `BGP UPDATE` message structure looks like this (simplified):

```
BGP UPDATE
  Withdrawn Routes Length: 0
  Total Path Attribute Length: 28
  Path Attributes:
    ORIGIN: IGP (0)
    AS_PATH: 65002
    NEXT_HOP: 192.0.2.5
  Network Layer Reachability Information:
    203.0.113.0/24
```

No fancy path manipulation. No community tags (yet). Just a clean, simple announcement that says "this prefix originates here."

### 3. Propagation (t=30s to t=5m)

Your upstream receives the UPDATE, validates it against their policy (or doesn't), and propagates it to their upstreams and peers.

Typical propagation timing:

- Immediate upstream: 10-30 seconds
- Tier-2 providers: 1-3 minutes
- Global route collectors: 2-5 minutes
- Full internet convergence: 5-15 minutes

During this window, some portion of the internet believes you're the legitimate origin for the victim's prefix. How 
much depends on `AS-PATH` length, local preference, and whether the victim's routes are still being announced (they 
usually are, creating an active conflict).

### 4. Impact window (t=5m to t=120m)

Traffic starts arriving at your AS instead of the victim's. If you're not forwarding it onwards (you probably aren't, 
in this scenario), it blackholes. The victim's services become unreachable from affected regions.

How much traffic? Depends on propagation reach. Could be 5%, could be 80%. The internet doesn't fail uniformly.

### 5. Withdrawal (t=120m)

After sufficient chaos (or before detection becomes too sophisticated), you withdraw the route.

```
router bgp 65002
 no network 203.0.113.0 mask 255.255.255.0
```

`BGP WITHDRAWAL` message:

```
BGP UPDATE
  Withdrawn Routes Length: 5
  Withdrawn Routes:
    203.0.113.0/24
  Total Path Attribute Length: 0
```

The internet re-converges to the victim's legitimate announcement. Services restore. Logs fill with confused error 
messages. And you vanish back into the background noise of routing instability.

### Propagation timing expectations

Optimistic scenario (good propagation):

- t=0: Announcement sent
- t=30s: Visible on RIS/RouteViews collectors
- t=2m: 30% of internet sees your route
- t=5m: 60% of internet sees your route
- t=10m: Propagation stabilises

Pessimistic scenario (filtered by many networks):

- t=0: Announcement sent
- t=30s: Visible on RIS/RouteViews collectors
- t=2m: 10% of internet sees your route
- t=5m: 15% of internet sees your route
- Propagation stalls (too many filters, RPKI enforcement)

Real-world propagation is messy and unpredictable. Route preferences vary by `AS`. Some networks have aggressive 
filtering. Others accept anything. You won't know until you try.

### Withdrawal mechanics

Clean withdrawal is important for plausible deniability. You want to look like someone who made a mistake and 
corrected it, not someone who's covering their tracks.

Good withdrawal:

- Send BGP WITHDRAWAL for the prefix
- Wait for convergence (5-10 minutes)
- Check route collectors to confirm removal
- Don't immediately disappear (stay online, respond to queries if contacted)

Bad withdrawal:

- Shut down BGP sessions abruptly (screams "attack")
- Withdraw and immediately disconnect all peering (suspicious)
- Withdraw multiple unrelated prefixes simultaneously (no legitimate reason)

If contacted by upstreams or the victim, your story is simple: "Configuration error during maintenance. Rolled back. 
Our apologies for the disruption."

## Expected theatre

### What breaks, what doesn't

What breaks:

- Services hosted on the hijacked prefix become unreachable from affected regions
- TCP connections time out
- UDP packets vanish into the void
- DNS queries for the victim's domain fail (if their nameservers are on the hijacked prefix)
- Monitoring systems light up with unreachability alerts

What doesn't break:

- Regions that never received your announcement continue working normally
- Cached DNS entries may continue to work (for a while)
- Services with geographic redundancy fail over to unaffected regions
- The victim's legitimate BGP announcements keep running (creating routing conflict, not total silence)

The failure mode is partial, geographically inconsistent unavailability. Not a clean outage. More like service 
degradation that varies by location and ISP. Which makes diagnosis harder and buys you time.

### Victim's perspective vs observer's perspective

Victim's perspective: They see monitoring alerts for unreachability. Some users can't connect. Others are fine. 
Traceroutes show packets entering the network and then... nothing. Or arriving at the wrong AS entirely.

If they check BGP route collectors, they'll see an unexpected announcement of their prefix from your AS. If they 
know to look. Most don't check until someone tells them. Usually Twitter, these days.

The victim can't unilaterally fix this. They can't withdraw your announcement. They can't force upstreams to prefer 
their route. They're at the mercy of the routing system's autonomous convergence and their upstream providers' 
willingness to implement filters.

Observer's perspective: An outside observer (monitoring BGP feeds, threat intelligence, security research) sees:

- New origin AS for a known prefix
- Short-lived announcement (minutes to hours)
- Geographic inconsistency (some regions affected, others not)
- Withdrawal without explanation

To a trained eye, this looks like either:

1. Operational error (Occam's razor, most likely)
2. Deliberate hijack with quick exit
3. Testing/reconnaissance for a larger attack

Distinguishing between (1) and (2) requires context. Time of day, victim profile, previous history, whether there's 
a ransom demand or follow-up attack.

### Plausible deniability maintenance

The key to maintaining deniability is looking incompetent, not malicious.

Do:

- Withdraw promptly (within 2 hours)
- Respond to queries with "configuration error"
- Provide plausible technical detail if pressed ("junior engineer applied wrong template")
- Continue normal BGP operations afterward (don't disappear)

Don't:

- Hijack multiple unrelated prefixes simultaneously (pattern recognition)
- Time your attack to coincide with other events (correlation)
- Demand ransom (removes all ambiguity)
- Use the hijacked traffic for obvious malicious purposes (interception, injection)
- Repeat the attack multiple times (establishes pattern)

If you want this to look like a mistake, act like someone who made a mistake. Embarrassed, apologetic, quick to fix, 
and keen to move on. Not defensive, not evasive, not suspiciously knowledgeable about operational security.

## Lantern fuel

### Log formats to generate

When running 
[🐙 this scenario in simulation](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/easy/fat_finger_hijack), 
generate events that mimic what real infrastructure would produce.

`BGP UPDATE` (announcement):

```json
{
  "event_type": "bgp.update",
  "timestamp": 1703001234,
  "source": {
    "feed": "ris",
    "observer": "rrc00"
  },
  "attributes": {
    "prefix": "203.0.113.0/24",
    "as_path": [3333, 65002],
    "origin_as": 65002,
    "next_hop": "192.0.2.5",
    "origin_type": "IGP"
  },
  "scenario": {
    "name": "fat-finger-hijack",
    "attack_step": "announce"
  }
}
```

Router syslog (upstream receiving announcement):

```
<189>1 2024-12-20T10:15:23Z router-r1 bgpd - - - %BGP-5-ADJCHANGE: neighbor 192.0.2.1 Up
<189>1 2024-12-20T10:15:34Z router-r1 bgpd - - - %BGP-4-DUPORIGINAS: Duplicate origin AS 65002 for prefix 203.0.113.0/24
```

BGP WITHDRAWAL:

```json
{
  "event_type": "bgp.withdraw",
  "timestamp": 1703008434,
  "source": {
    "feed": "ris",
    "observer": "rrc00"
  },
  "attributes": {
    "prefix": "203.0.113.0/24",
    "withdrawn_by_as": 65002
  },
  "scenario": {
    "name": "fat-finger-hijack",
    "attack_step": "withdraw"
  }
}
```

### Timing characteristics

Events don't happen instantaneously. Real BGP propagation has jitter, variable delays, and geographic spread.

Announcement propagation:

- First collector sees UPDATE: t+10s to t+60s
- 50% of collectors see UPDATE: t+2m to t+5m
- 90% propagation: t+5m to t+15m

Withdrawal propagation:

- First collector sees WITHDRAWAL: t+10s to t+60s
- 50% convergence: t+1m to t+3m
- 90% convergence: t+3m to t+10m

ToDo: Add Gaussian noise to these timings. Real networks don't operate with millisecond precision.

### Volume and frequency

For a single-prefix hijack:

- BGP UPDATE messages: 10-50 (one per peer/upstream, propagated to their peers)
- Route collector observations: 5-20 (depends on how many you're subscribed to)
- Router syslog messages: 2-10 (depending on router verbosity)
- Monitoring alerts: 5-50 (victim's monitoring, if they have it)

Frequency of legitimate events (for context):

- BGP UPDATEs globally: ~millions per day
- Your AS announcing routes: hundreds to thousands per day
- Route flaps and instability: constant background noise

This hijack is one event in an ocean of routing changes. Without specific monitoring for its prefix or AS, it's 
easily missed.

### JSON/syslog examples

See the [🐙 telemetry/generators/](https://github.com/ninabarzh/red-lantern-sim/tree/main/telemetry/generators) 
directory for complete mock data generators that produce realistic logs. Intent is consistency with real-world formats.

RIS-format BGP message:

```json
{
  "type": "UPDATE",
  "timestamp": 1703001234,
  "collector": "rrc00.ripe.net",
  "peer": "3333",
  "peer_asn": 3333,
  "announcements": [{
    "next_hop": "192.0.2.5",
    "prefixes": ["203.0.113.0/24"]
  }],
  "path": [3333, 65002],
  "origin": "IGP"
}
```

Cisco IOS syslog:

```
%BGP-5-ADJCHANGE: neighbor 192.0.2.1 Up
%BGP-4-DUPORIGINAS: Duplicate origin AS 65002 for prefix 203.0.113.0/24
%BGP-6-INSTALL: Route 203.0.113.0/24 via 192.0.2.1 installed in table
```

Junos syslog:

```
rpd[1234]: BGP_PREFIX_THRESH_EXCEEDED: 192.0.2.1 (External AS 65002): Prefix limit exceeded
rpd[1234]: bgp_nexthop_sanity_check: 192.0.2.1 (External AS 65002): Next hop 192.0.2.5 is not directly connected
```

## The aftermath

### What remains in logs

After the attack, several log sources will contain evidence. The question is whether anyone's looking.

BGP route collectors (RIPE RIS, RouteViews):

- Announcement timestamp
- Originating AS (yours)
- AS-PATH traversed
- Withdrawal timestamp
- Duration of announcement

This data is public and permanent. If someone investigates, they'll find it. But route collector data is noisy and 
high-volume. Unless you gave them a reason to look specifically at your AS and this prefix, it's a needle in a 
routing-table-sized haystack.

Victim's router logs:

- Duplicate origin AS warnings
- Next-hop changes
- Route preference calculations
- Possibly prefix-limit alerts if they have those configured

If the victim has centralised logging and retention, this evidence exists. If they're forwarding syslogs to `/dev/null` 
(depressingly common), it doesn't.

Upstream provider logs:

- Your BGP session establishing the route
- The announcement being accepted
- Propagation to their peers
- The withdrawal

Whether upstreams retain this, and whether they'll share it with investigators, varies wildly. Some providers log 
everything. Others consider it proprietary. Many don't log BGP in detail at all.

Monitoring system alerts:

- Service unreachability alerts
- Latency spikes
- Traceroute anomalies

If the victim has proper monitoring (many don't), they'll have a timeline of when things broke and when they recovered. 
If they correlate this with BGP data (few do), they might identify the hijack. If they investigate further (very few 
do), they might identify you.

### What routing history shows

BGP history is available from several sources:

- [RIPE RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris) maintains historical data
- [RouteViews](http://www.routeviews.org/) archives routing tables
- [BGPStream](https://bgpstream.caida.org/) provides queryable historical data
- Commercial threat intelligence providers monitor BGP

A competent investigator can reconstruct:
- When your announcement appeared
- Which collectors saw it
- How widely it propagated
- When it was withdrawn
- What your AS normally announces (establishing context)

They can also check:
- Whether you have a history of misannouncements
- Whether this prefix is related to your allocated address space (it isn't)
- Whether similar hijacks have originated from your AS before

The data exists. Whether anyone looks at it depends on whether the incident was severe enough, visible enough, and 
suspicious enough to warrant investigation.

### Attribution difficulty

In theory, attributing this attack is trivial. Your AS number is in the logs. You announced the prefix. It's right 
there in the route collectors.

In practice, attribution is complicated by:

Legitimate confusion:

- Was it deliberate or a mistake?
- Was it your fault or your upstream's routing policy error?
- Was it malicious or incompetent?

Operational complexity:

- Shared AS numbers (some hosting providers sub-allocate)
- Compromised customer accounts (someone else using your infrastructure)
- Misconfigured automation (scripts gone wrong)

Limited investigation resources:

- Most incidents don't warrant deep investigation
- BGP expertise is scarce
- Cross-border coordination is slow
- Legal frameworks for BGP hijacking are murky

Plausible deniability:

- "Configuration error during maintenance"
- "Junior engineer applied wrong template"
- "Automated failover gone wrong"

Unless you've done something egregiously obvious (demanded ransom, repeated the attack, intercepted sensitive traffic), attribution stops at your AS number and the word "mistake." Proving malicious intent requires more evidence than most investigators have time or authority to gather.

That said, this is 2025. If you're a threat intelligence target, assume BGP monitoring exists. If you're not, assume no one's watching.

## Some thoughts

This is simultaneously the stupidest and most effective BGP attack available. Stupid because it's exactly what 
happens during routine operational errors. Effective because no one expects deliberate malice disguised as 
incompetence.

In a just world, this attack wouldn't work. RPKI would be universally deployed with strict enforcement. Upstreams 
would validate announcements against IRR databases. Prefix filters would be mandatory and comprehensive. Monitoring 
would catch anomalies in seconds.

We don't live in that world.

We live in a world where "fat-finger" is an acceptable excuse, where BGP trusts whoever speaks loudest, and where 
routing security is a patchwork of best-effort filters that may or may not be configured correctly.

Use this knowledge responsibly. Or at least plausibly deniably.

## Related reading

- [BGP Operations and Security (RFC 7454)](https://tools.ietf.org/html/rfc7454)
- [The Resource Public Key Infrastructure (RFC 6480)](https://tools.ietf.org/html/rfc6480)
- Real incidents: [YouTube hijack (Pakistan Telecom, 2008)](https://www.ripe.net/about-us/news/youtube-hijacking-a-ripe-ncc-ris-case-study/), [Amazon Route53 hijack (2018)](https://www.internetsociety.org/blog/2018/04/amazons-route-53-bgp-hijack/), [Cloudflare incident (2020)](https://blog.cloudflare.com/cloudflare-outage-on-july-17-2020/)

## Tools mentioned

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
- [RIPE RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris)
- [RouteViews](http://www.routeviews.org/)
- [BGPStream](https://bgpstream.caida.org/)