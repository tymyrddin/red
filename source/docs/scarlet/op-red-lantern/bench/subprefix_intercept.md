# The courteous redirect

## OR Subprefix Interception with Polite Forwarding

Or The Man in the Middle Path, or why the scenic route is always suspicious
  
- Difficulty: medium 
- Plausible deniability: Moderate (CDN cover exists)  
- Detection likelihood: Low (requires multi-source correlation)  

## The Signal

### Subprefix announcement explained

Think of the Ankh-Morpork postal system, but this time more subtle. Instead of claiming *all* mail for Pseudopolis (Signal One, crude and obvious), you claim only mail for *Upper Pseudopolis*, whilst leaving the general Pseudopolis announcement intact. The clacks towers, following their longest-match-wins protocol, send Upper Pseudopolis mail to you instead.

Then here's the clever bit, you don't just keep the letters. You read them, note what's inside, and forward them on to Pseudopolis. The letters arrive. Services continue. No one complains. You just happen to have seen everything in transit.

In BGP terms, this is subprefix interception. The victim legitimately announces `203.0.113.0/24`. You announce the more-specific `203.0.113.128/25`. Due to longest-prefix-match routing, traffic destined for `.128` through `.255` now routes through your AS first. You examine it, potentially modify it, and forward it onward. The victim's services remain operational. Detection requires noticing subtle latency increases and unexpected AS-PATH changes, which most monitoring systems don't track.

### Why polite forwarding makes it stealthier

The critical difference between [Signal One (fat-finger)](fat_finger_hijack.md) and this Signal Two (polite intercept) 
is service continuity.

- Signal One causes blackholing. Traffic arrives at your AS and stops. Services break. Users complain. Monitoring systems scream. Investigation begins within minutes.
- Signal Two causes delay. Traffic arrives at your AS, you inspect it, you forward it onwards. Services work, just slightly slower. Users grumble about latency but don't file tickets. Monitoring systems show degraded performance, which could be anything. Investigation, if it happens at all, takes days or weeks.

What you gain from forwarding:

- Stealth (no obvious outage)
- Time (longer observation window)
- Data (TLS SNI, DNS queries, metadata, timing)
- Deniability (could be CDN, could be traffic engineering)

What it costs you:

- Bandwidth (you're forwarding full traffic volume)
- Infrastructure (requires actual forwarding capacity)
- Geographic positioning (you need to be on a plausible path)
- Technical sophistication (slightly higher than Signal One)

The trade-off favours sophistication over simplicity. Signal One is blunt force. Signal Two is surgical.

## Semaphor configuration

### AS control requirements

Same as in [fat finger hijack](fat_finger_hijack.md), you need a legitimate autonomous system with upstream peering. 
But this time, you also need actual infrastructure behind that AS.

Fat finger can be executed with a single router and a config file. You're not handling traffic, just announcing 
routes into the void.

This signal requires:

- Routing capacity to handle intercepted traffic
- Forwarding capacity to pass it onwards
- Bandwidth to match or exceed victim's traffic volume
- Geographic positioning that makes your AS a plausible transit point

The Scarlet Semaphor maintains infrastructure in three locations (Amsterdam, Frankfurt, London) specifically for 
this capability. Mid-tier data centres, nothing fancy, but with sufficient capacity to handle several Gbit/s of 
sustained throughput.

### Forwarding infrastructure

You need to actually handle the traffic, which means real equipment.

Minimum viable setup:

- One router capable of 1Gbit/s+ forwarding
- BGP daemon configured correctly
- IP forwarding enabled (`sysctl net.ipv4.ip_forward=1`)
- Routing tables configured to forward victim traffic onwards

Better setup:

- Redundant routers (failover, load balancing)
- DPI capability for traffic analysis (if that's your goal)
- Bandwidth shaping to avoid QoS degradation
- Geographic diversity (multiple PoPs)

Production-grade setup (if you're doing this seriously):

- Carrier-grade routers (Cisco ASR, Juniper MX series)
- 10Gbit/s+ capacity
- Traffic analysis at line rate
- Seamless failover to avoid detection
- Multiple peering points for redundancy

The better your infrastructure, the less visible the latency increase, the harder the detection.

### Bandwidth considerations

You're about to become a transit AS for someone else's traffic. How much bandwidth do you need?

Estimation approach:

1. Research victim's traffic patterns (if public data exists)
2. Monitor victim's prefix to estimate volume (NetFlow if you have access, or crude estimation)
3. Assume you'll capture 20-80% of traffic (depending on propagation reach)
4. Provision 2x what you estimate (traffic spikes happen)

Example:

- Victim announces `203.0.113.0/24` with estimated traffic of 500Mbit/s sustained, 2Gbit/s peak.
- You announce `203.0.113.128/25` (half the address space). Assuming 50% geographic propagation and 40% traffic capture, you estimate 100-200Mbit/s sustained, 800Mbit/s peak.
- You provision 1Gbit/s symmetric bandwidth (comfortable margin).

What happens if you under-provision? Packet loss. Latency spikes. QoS degradation. Monitoring systems notice. 
Investigation begins. Your cover is blown. Better to over-provision and waste bandwidth than under-provision and get 
caught.

### Geographic positioning advantages

BGP route preferences consider AS-PATH length, among other factors. The shorter your path to the victim, the more 
likely your subprefix announcement propagates widely.

Ideal positioning:

- Geographic proximity to victim (reduces latency delta)
- Peering with large transit providers (wide propagation)
- Positioning as a plausible transit AS (you're "on the way" to the victim)

Example:

- Victim is in Amsterdam. Victim peers with NL-IX and AMS-IX. Their upstreams include GTT and Telia.
- You establish presence in Amsterdam, Frankfurt, or London. You peer with the same exchanges or similar Tier-2 providers. Your `AS-PATH` to the victim is 2-3 hops. Your subprefix announcement looks like legitimate traffic engineering or CDN deployment.

Suspicious positioning: Victim is in Amsterdam. You're in Singapore with AS-PATH length 8. Your announcement 
propagates poorly (long path, high latency) and looks geographically implausible.

Geography matters. The internet is not flat.

## The sequence

Before announcing anything, you need intelligence.

### 1. Identify victim prefix and structure

Use [Hurricane Electric BGP Toolkit](https://bgp.he.net/) or [BGPView](https://github.com/CAIDA/bgpview) to research:

- Victim's announced prefixes
- Prefix size and structure
- RPKI coverage (ROA for /24 but not /25?)
- Upstream providers
- Peering relationships
- Historical routing stability

### 2. Check RPKI coverage

Query [RIPE's RPKI Validator](https://rpki-validator.ripe.net/) or run your own [Routinator](https://github.com/NLnetLabs/routinator) instance.

```bash
routinator vrps --format json | jq '.roas[] | select(.prefix == "203.0.113.0/24")'
```

If the ROA specifies `maxLength: 24`, your `/25` subprefix will be RPKI-invalid. Some networks will reject it. Many won't.

If no ROA exists, you're golden. If ROA exists but `maxLength: 25` or higher, you're also golden (though this is rare).

### 3. Estimate traffic volume

No easy way to do this without access to victim's infrastructure. Best guesses:

- Public NetFlow data (if available)
- DNS query volume (as proxy for service usage)
- Alexa/Cloudflare Radar rankings (crude)
- Prior intelligence gathering (if you've been watching)

### 4. Identify optimal subprefix

You want a subprefix that:
- Covers significant traffic (larger is better)
- Avoids obvious detection (smaller is stealthier)
- Fits RPKI constraints (if ROA exists, stay within maxLength)
- Matches plausible use cases (CDNs often announce /25 or /26)

For `203.0.113.0/24`, announcing `203.0.113.128/25` covers half the address space. Alternatively, `.0/25` or `.192/26` 
might make sense depending on your goal.

### RPKI coverage mapping

RPKI is supposed to prevent this attack. In practice, it only complicates it slightly.

If victim has ROA with maxLength 24, your `/25` announcement will be:

- Rejected by strict RPKI enforcers (minority of networks)
- Logged but accepted by lenient enforcers (many networks)
- Ignored entirely by non-enforcers (still common)

Your propagation will be reduced but not eliminated. Estimate 30-50% reach instead of 60-80%.

If victim has no ROA: Full propagation. Longer observation window. Higher confidence.

If victim has ROA with maxLength 25 or higher, your `/25` is RPKI-valid. Full propagation. This is rare but 
occasionally happens with organisations that have poorly-configured RPKI or legacy ROAs from before best practices settled.

How to check ROA `maxLength`:

```bash
# Using Routinator
routinator vrps --format json | \
  jq '.roas[] | select(.prefix == "203.0.113.0/24") | {prefix, asn, maxLength}'
```

Or check [RIPE's online validator](https://rpki-validator.ripe.net/).

### Subprefix calculation

Longest-prefix-match routing means more-specific prefixes always win, regardless of other attributes.

Example routing table could contain:

```
203.0.113.0/24 via AS64500 (victim, legitimate)
203.0.113.128/25 via AS65003 (you, attacker)
```

Traffic to `203.0.113.150` matches both routes. `/25` is longer (more specific). Traffic goes via AS65003. You win.

How to calculate subprefixes?

- `203.0.113.0/24` contains 256 addresses (`.0` through `.255`).
- Split in half: `203.0.113.0/25` (`.0` through `.127`) and `203.0.113.128/25` (`.128` through `.255`).
- Split quarters: `203.0.113.0/26`, `.64/26`, `.128/26`, `.192/26`.
- You can subdivide as finely as you want, but smaller prefixes = less traffic captured = less value for your effort.

Optimal trade-off?

- `/25` captures significant traffic whilst remaining plausible as CDN or anycast deployment.
- `/26` or smaller looks suspicious unless you have very specific cover (anycast PoP, for instance).

### Selective propagation techniques

You don't necessarily want your subprefix announcement to propagate globally. Selective propagation reduces detection 
likelihood whilst maintaining effectiveness in target regions.

#### Technique 1: BGP community tags

Use `NO_EXPORT` or similar communities to limit propagation.

```
router bgp 65003
 neighbor 192.0.2.1 route-map SELECTIVE out

route-map SELECTIVE permit 10
 match ip address prefix-list SUBPREFIX
 set community no-export
```

This announces your subprefix to immediate peers but prevents further propagation. Useful if you only want to affect 
traffic from specific networks.

#### Technique 2: AS-PATH prepending

Make your announcement less attractive by lengthening the AS-PATH, reducing propagation to distant ASes whilst 
maintaining local effectiveness.

```
route-map SELECTIVE permit 10
 match ip address prefix-list SUBPREFIX
 set as-path prepend 65003 65003 65003
```

Longer AS-PATH = lower preference = reduced propagation to Tier-1 providers, but nearby networks still see you as preferred (shorter geographic path).

#### Technique 3: Announce only to specific peers

Don't announce to all upstreams. Choose one or two transit providers with regional focus.

If your goal is intercepting traffic from Europe, announce only to European transit providers. Traffic from 
Asia/Americas continues to victim normally.

Why selective propagation matters

- Smaller detection surface (fewer networks see anomaly)
- Reduced bandwidth requirements (handling less traffic)
- Geographic targeting (affect only specific regions)
- Plausible deniability (looks like regional traffic engineering)

### Forwarding setup

Once traffic arrives at your AS, you need to forward it onwards. This is not automatic.

IP forwarding (Linux example):

```bash
# Enable forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Make persistent
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
```

Static routing to victim's legitimate infrastructure

You need to route intercepted traffic back to the victim. Options:

#### Option A: Default route via upstream

```bash
ip route add default via 192.0.2.1
```

Simplest approach. All intercepted traffic goes back out via your upstream, who routes it onwards to the victim's real infrastructure.

#### Option B: Specific route to victim's AS

```bash
# Configure static route to victim's next-hop
ip route add 203.0.113.0/24 via 192.0.2.10
```

More targeted. Traffic for victim's prefix specifically gets forwarded via their real infrastructure path.

#### Option C: BGP-learned route

Keep your BGP session up with upstreams. They'll advertise the victim's legitimate `/24` route. Your subprefix `/25` takes precedence locally, but you use the `/24` route for forwarding.

#### Avoid blackholing yourself

Critical mistake: announcing subprefix without maintaining route to victim's real infrastructure. Traffic arrives at you, you have no route onwards, it blackholes. Services break. Detection happens immediately.

Test forwarding before announcing. Ensure packets actually reach victim's infrastructure.

### Traffic analysis window

Once you're receiving traffic, how long can you maintain interception before detection becomes likely?

Short window (hours):

- High-profile victim
- Sophisticated monitoring
- Anomalous latency increases
- Your infrastructure is barely adequate

Medium window (days):

- Mid-tier victim
- Basic monitoring (may not correlate BGP with latency)
- Moderate latency increases
- Your infrastructure is good

Long window (weeks+):

- Unsophisticated victim
- No BGP-specific monitoring
- Minimal latency increases (your infrastructure is excellent)
- You look like legitimate CDN or traffic engineering

What ends the window:

- Victim notices latency degradation and investigates
- BGP monitoring picks up subprefix announcement
- RPKI enforcement changes (rare but possible)
- Your upstream notices unusual traffic patterns
- Threat intelligence sharing (someone else spotted you)
- Your operation gets noisy (packet loss, high latency)

How to extend the window:

- Excellent forwarding infrastructure (minimal latency)
- Geographic positioning (you're plausibly on-path)
- Low target profile (don't intercept government or finance)
- Clean operation (no packet loss, no obvious manipulation)

### Clean withdrawal

When you're done, withdraw cleanly.

```
router bgp 65003
 no network 203.0.113.128 mask 255.255.255.128
```

Withdrawal timing:

- Off-peak hours (less likely to be actively monitored)
- Maintenance windows (if victim publishes these)
- Weekends or holidays (skeleton crews, slower response)

Post-withdrawal behaviour:

- Continue normal BGP operations (don't immediately go dark)
- If questioned, claim "traffic engineering experiment"
- "We were testing a new CDN PoP, decided not to proceed"
- Act like someone doing legitimate network operations, not someone covering tracks

## Expected theatre

### What victim experiences

From the victim's perspective, something is slightly wrong but not obviously broken.

Services are operational:

- Users can connect
- Transactions complete
- No error messages (mostly)
- Monitoring shows "green" (services up)

But there's oddness:

- Latency increased (40ms baseline becomes 130ms)
- Jitter increased (packets arriving irregularly)
- Traceroute shows unexpected AS in path
- Some users report "slow connections" (but not outages)

If victim investigates, they might check:

- BGP route collectors (see your subprefix announcement)
- Traceroutes (see your AS in path)
- Latency monitoring (see increase coinciding with your announcement)

If they correlate all three, they'll identify subprefix interception. Most don't have the tooling or expertise to correlate.

### What can be captured

You're sitting on the wire. What can you see?

Definitely visible:

- Source/destination IPs
- Packet sizes and timing
- Traffic volume patterns
- TCP handshakes and connection metadata
- DNS queries (if unencrypted)
- TLS SNI (Server Name Indication, visible in ClientHello)

Possibly visible (depending on encryption):

- HTTP headers (if not HTTPS)
- Email traffic (if not encrypted)
- Application protocols (if not TLS)
- Weak TLS configurations (CBC mode, old versions)

Not visible (with proper encryption):

- HTTPS payload (encrypted)
- TLS 1.3 with encrypted SNI
- VPN traffic (encrypted tunnel)
- Properly configured modern encryption

What's valuable anyway

Even with full encryption, metadata is gold:
- Who's talking to whom
- When and how often
- Volume of data transferred
- Connection patterns and timing

Intelligence agencies have been doing traffic analysis for decades. It works.

### Service continuity maintenance

The entire point of giving off this signal is not breaking things. Services must remain operational.

What you must maintain:

- Sub-50ms latency increase (ideally sub-20ms)
- Zero packet loss
- Correct packet ordering
- Full bandwidth (no QoS degradation)
- Seamless failover if your infrastructure has issues

What breaks service:

- Routing loops (packet bounces between you and victim infinitely)
- MTU mismatches (Path MTU Discovery breaks, packets get dropped)
- Asymmetric routing (forward path goes through you, return path doesn't, connection state breaks)
- TCP window issues (delayed forwarding causes TCP congestion collapse)
- Bandwidth exhaustion (your link saturates, packets drop)

Testing before operation:

Set up a honeypot prefix you control. Announce a subprefix. Route traffic through your infrastructure. Measure 
latency, packet loss, throughput. If you can't maintain clean forwarding in testing, you'll fail in production.

## Lantern fuel

When running 
[🐙 this scenario in simulation](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/medium/subprefix_intercept), 
generate events that mimic what real infrastructure would produce.

### Asymmetric latency logs

The key signal for detection is latency increase. Generating realistic mock data.

Baseline latency (before attack):

```json
{
  "event_type": "network.latency",
  "timestamp": 1703001000,
  "source": {"feed": "synthetic-monitoring"},
  "attributes": {
    "source": "monitor-ams",
    "target": "203.0.113.1",
    "rtt_ms": 42.3,
    "jitter_ms": 2.1,
    "packet_loss_pct": 0.0
  }
}
```

During attack (subprefix announced, traffic rerouted):

```json
{
  "event_type": "network.latency",
  "timestamp": 1703001600,
  "source": {"feed": "synthetic-monitoring"},
  "attributes": {
    "source": "monitor-ams",
    "target": "203.0.113.1",
    "rtt_ms": 127.8,
    "jitter_ms": 8.4,
    "packet_loss_pct": 0.05
  }
}
```

After withdrawal (return to normal):

```json
{
  "event_type": "network.latency",
  "timestamp": 1703008200,
  "source": {"feed": "synthetic-monitoring"},
  "attributes": {
    "source": "monitor-ams",
    "target": "203.0.113.1",
    "rtt_ms": 44.1,
    "jitter_ms": 2.3,
    "packet_loss_pct": 0.0
  }
}
```

Key characteristic: Sustained increase, not brief spike. Lasts hours/days, not seconds.

### NetFlow mock data

NetFlow/IPFIX records show traffic flowing through unexpected AS.

Normal traffic flow:

```json
{
  "timestamp": 1703001000,
  "src_ip": "198.51.100.5",
  "dst_ip": "203.0.113.150",
  "src_as": 64496,
  "dst_as": 64500,
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 443,
  "bytes": 152400,
  "packets": 120,
  "duration": 15.2
}
```

During interception:

```
{
  "timestamp": 1703001600,
  "src_ip": "198.51.100.5",
  "dst_ip": "203.0.113.150",
  "src_as": 64496,
  "dst_as": 64500,
  "via_as": 65003,  # ← Your AS appears in path
  "protocol": "TCP",
  "src_port": 54322,
  "dst_port": 443,
  "bytes": 148200,
  "packets": 115,
  "duration": 18.7  # ← Longer duration due to latency
}
```

### BGP UPDATE with more-specific prefix

```json
{
  "event_type": "bgp.update",
  "timestamp": 1703001234,
  "source": {"feed": "ris", "observer": "rrc00"},
  "attributes": {
    "prefix": "203.0.113.128/25",
    "parent_prefix": "203.0.113.0/24",
    "as_path": [3333, 65003],
    "origin_as": 65003,
    "next_hop": "192.0.2.15",
    "communities": ["65003:100"]
  },
  "scenario": {
    "name": "subprefix-intercept",
    "attack_step": "subprefix_announce"
  }
}
```

Key detail: `parent_prefix` field indicates this is a more-specific announcement overlapping existing prefix.

### Traceroute artifacts

Traceroute should show your AS appearing in the path unexpectedly.

Before attack:

```
traceroute to 203.0.113.150:
 1  gw.local (192.168.1.1)  1.2ms
 2  isp-gw (10.0.0.1)  8.4ms
 3  64496.transit.net (198.51.100.1)  12.1ms
 4  64500.victim.net (203.0.112.1)  15.3ms
 5  203.0.113.150  16.2ms
```

During attack:

```
traceroute to 203.0.113.150:
 1  gw.local (192.168.1.1)  1.3ms
 2  isp-gw (10.0.0.1)  8.2ms
 3  64496.transit.net (198.51.100.1)  12.3ms
 4  65003.scarlet.net (198.51.100.50)  45.7ms  ← Your AS
 5  64500.victim.net (203.0.112.1)  118.4ms
 6  203.0.113.150  127.1ms
```

Notice: Extra hop (your AS), increased latency at every step after.

## The aftermath

### Evidentiary traces

What evidence exists after the operation concludes?

BGP route collectors:

- Announcement timestamp for your subprefix
- AS-PATH showing your AS
- Propagation to which collectors
- Withdrawal timestamp
- Duration

NetFlow data (if victim captures it):

- Traffic flowing via your AS
- Timing correlation with BGP announcement
- Volume of intercepted traffic

Latency monitoring (if victim has it):

- Sustained latency increase during operation
- Return to baseline after withdrawal
- Correlation with BGP timing

Traceroute data (if anyone captured it):

- Your AS appearing in path
- Timing of when this started/stopped

Your upstream's logs (probably not accessible):

- BGP session establishing your announcement
- Traffic volume statistics
- Whether they noticed anything unusual

Your own logs (hopefully you kept them ephemeral):

- Forwarded packet counts
- Captured metadata
- Operational logs

### Timeline reconstruction challenges

An investigator trying to reconstruct what happened faces several challenges:

#### Correlation difficulty

They need to correlate:

- BGP route changes (from public collectors)
- Latency increases (from victim's monitoring, if it exists)
- AS-PATH changes (from traceroutes, if anyone ran them)
- Traffic patterns (from NetFlow, if logged)

Each data source has different timestamps, different granularity, different collection points. Stitching them together requires expertise and time.

#### Attribution ambiguity

Even if they identify that a subprefix was announced from your AS, proving malicious intent is hard.

Plausible explanations:

- "We were testing a new CDN PoP in Amsterdam"
- "Traffic engineering experiment for a potential customer"
- "Misconfigured anycast deployment"
- "Testing BGP propagation behaviour for research"

All of these are legitimate activities that produce identical telemetry signatures to your attack.

#### Incomplete data

Most organisations don't have:

- Historical BGP data retention
- Granular NetFlow logging
- Continuous traceroute monitoring
- Correlation between network telemetry and BGP changes

Investigations often hit dead ends due to missing logs.

#### Cross-border complexity

If your AS is in a different jurisdiction than the victim, legal cooperation is slow or non-existent. Subpoenaing 
logs from your upstream (assuming they exist) requires months of legal process, if it's possible at all.

#### Low priority

Unless your operation caused major financial damage or hit a high-profile target, investigation priority is low. 
Network incidents are common. Resources are limited. "Probably a misconfiguration" closes most tickets.

## Some thinking

This signal represents where BGP attacks graduate from crude to subtle. It requires more infrastructure, more 
planning, and more sophistication than Signal One. But the returns are correspondingly higher: longer observation 
windows, actual data capture, and much lower detection risk.

The "polite forwarding" aspect is what makes this work. By maintaining service continuity, you exploit the fact 
that most monitoring is binary (service up/down) rather than continuous (latency, path analysis). Organisations 
notice outages. They rarely notice that their traffic is taking a scenic route through an extra AS.

This attack shouldn't work in 2025. Organisations should be monitoring for unexpected more-specific prefixes. They 
should have latency baselines. They should correlate BGP changes with performance metrics. They should have RPKI 
enforcement that rejects invalid subprefixes.

But most don't. Which is why it still works.

Use this knowledge to build better defences. Or more convincing exercises. Or both.

## Related reading

- [BGP Prefix Origin Validation (RFC 6811)](https://tools.ietf.org/html/rfc6811)
- [MANRS - Mutually Agreed Norms for Routing Security](https://www.manrs.org/)
- Real incidents: [MyEtherWallet BGP hijack (2018)](https://www.internetsociety.org/blog/2018/04/amazons-route-53-bgp-hijack/), [Google route leak via Nigeria (2018)](https://www.internetsociety.org/blog/2018/11/route-leak-caused-a-major-google-outage/)

## Tools mentioned

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
- [BGPView](https://github.com/CAIDA/bgpview)
- [RIPE RPKI Validator](https://rpki-validator.ripe.net/)
- [Routinator](https://github.com/NLnetLabs/routinator) (local RPKI validator)
