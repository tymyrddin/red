# Subprefix intercept (simulator scenario)

## From covert operation to training exercise

[The original subprefix intercept](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept) was executed by the Scarlet Semaphore with polite forwarding. Traffic was intercepted, examined, and forwarded onwards to maintain service. Victims noticed increased latency but services remained functional. This made the attack considerably harder to detect than crude hijacking.

It was also considerably more illegal.

Following [Patrician engagement](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/patrician-engagement), this operation was ceased and translated into simulator scenario for Department of Silent Stability training purposes. The Semaphore were encouraged (firmly) to share their methodology. They cooperated (eventually).

## What the simulator currently models

The live operation involved:
- BGP announcement of /25 within victim's /24
- Traffic interception via longest-prefix-match exploitation
- Packet forwarding through attacker infrastructure
- Latency increase from additional hop
- Sustained operation (8 minutes in this case)
- Clean withdrawal

The simulator models:
- BGP announcements (baseline /24, then more-specific /25)
- Routing best-path selection telemetry
- Latency metrics showing path change impact
- Syslog entries for route learning
- Withdrawal and restoration

What's preserved: The detection challenge. Services work, but something's wrong. Latency increased. Path changed. But nothing obviously broken.

What's simplified: No actual forwarding infrastructure. No real packet inspection. No sustained traffic interception. Timeline compressed from 8 minutes to simulation time.

## Scenario structure

```yaml
id: subprefix-intercept
timeline:
  - t: 0     # Scenario start
  - t: 5     # Baseline: victim announces /24
  - t: 60    # Attacker announces /25 (more-specific)
  - t: 65    # Traffic intercept confirmed
  - t: 70    # Latency spike detected
  - t: 300   # Maintain phase (sustained intercept)
  - t: 480   # Withdrawal
  - t: 485   # Latency returns to normal
```

This maps to [The Sequence](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept#the-sequence) from operational documentation:
- t=60: "Announce more-specific prefix"
- t=65: "Traffic routing confirmed via attacker AS"
- t=70: "Latency increase observed (baseline 45ms → 132ms)"
- t=480: "Withdrawal executed"

## Telemetry generation

From `telemetry.py`:

Baseline announcement:
```python
bgp_gen.emit_update(
    prefix="203.0.113.0/24",
    as_path=[65001],
    origin_as=65001,
    scenario={"attack_step": "baseline"}
)
```

Subprefix announcement:
```python
bgp_gen.emit_update(
    prefix="203.0.113.128/25",
    as_path=[65002, 65003],
    origin_as=65003,
    scenario={"attack_step": "subprefix_announce"}
)
```

Latency spike:
```python
latency_gen.emit(
    source_router="R1",
    target_router="203.0.113.128/25",
    latency_ms=132.0,  # Was 45ms baseline
    jitter_ms=8.5,
    packet_loss_pct=0.05
)
```

The latency change is the most visible indicator. From [operational notes](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept#expected-telemetry): "Latency metrics show 2-3x increase due to additional hop through attacker infrastructure."

## What defenders practice

Running this scenario trains analysts to:

Recognise more-specific prefix patterns
/25 appearing within known /24. Exploits longest-prefix-match. This is described in [the signal section](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept#the-signal): "Surgical traffic interception that leaves most services functional."

Correlate BGP with performance metrics
New BGP announcement coinciding with latency increase. Requires cross-system correlation. Many organisations collect both data sources but don't correlate them.

Distinguish polite hijack from service failure
Services still work, just slower. This looks like congestion, not attack. From operational docs: "Victims see degraded performance, not outage. Investigation priority is lower."

Understand forwarding can hide hijacks
If attacker forwards traffic onwards, services don't break. Traditional "did the service go down" detection fails. Need path analysis, not just reachability checks.

## What's missing (simulator limitations)

### No packet forwarding simulation

Live operation: "Attacker intercepts packets, examines headers/payloads, forwards to victim infrastructure."

Current simulator: No packet-level model. Latency metric implies forwarding happened, but there's no actual traffic flow showing packets traversing attacker AS.

Workaround: Latency increase from 45ms to 132ms suggests additional hop. Defenders infer forwarding from latency pattern, not from seeing actual packet paths.

### No sustained traffic analysis

Live operation: "8 minutes of traffic interception. Volume: ~500 Mbps sustained."

Current simulator: Timestamp t=300 marked "maintain" but no continuous telemetry showing ongoing traffic. Timeline jumps from t=70 (latency spike) to t=300 (maintain) to t=480 (withdraw).

Workaround: Single "maintain" entry represents sustained phase. Defenders must understand this represents 180 seconds of ongoing interception, not a momentary event.

### No AS path validation

Live operation: "Attacker AS64513 inserted itself into path. Path was [64512, 64513, 65001]. Should have been [64512, 65001]."

Current simulator: BGP telemetry shows AS path, but there's no baseline comparison engine saying "this path is suspicious because AS64513 doesn't normally appear between these peers."

Workaround: Defenders must manually compare current AS path with expected paths. No automated "path anomaly detected" signal.

### No service-layer visibility

Live operation: "HTTP connections show additional TLS handshake delay. TCP retransmissions increased 3x."

Current simulator: Only router-level telemetry. No application-layer metrics showing TLS timing, TCP behaviour, or HTTP response times.

Workaround: Latency metric is aggregate. Defenders must infer that HTTP, DNS, and all other protocols affected, but don't see protocol-specific impact.

## Running the scenario

```bash
# Clean run (easier to spot patterns)
python -m simulator.cli simulator/scenarios/easy/subprefix_intercept/scenario.yaml

# With background noise (realistic difficulty)
python -m simulator.cli simulator/scenarios/easy/subprefix_intercept/scenario.yaml --background

# Output to JSON for post-analysis
python -m simulator.cli simulator/scenarios/easy/subprefix_intercept/scenario.yaml \
  --output json --json-file subprefix_analysis.json
```

With background noise, the subprefix announcement gets lost among normal BGP updates. The latency spike might be one of dozens of latency alerts that day. This models [detection difficulty](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept#detection-in-practice): "Needle in haystack problem. Performance degradation happens constantly for various reasons."

## Suggestions for simulator improvements

### Feature request 1: Continuous traffic telemetry

Currently "maintain" phase (t=70 to t=480) is silent. No telemetry between these timestamps.

Implementation sketch:

```python
class TrafficGenerator:
    def emit_sustained_flow(self, start_t, end_t, interval):
        # Generate periodic telemetry showing ongoing traffic
        # NetFlow-style records every 30 seconds
        # Shows volume, source ASes, protocols
```

This would make sustained interception visible as ongoing pattern, not just single "maintain" marker.

### Feature request 2: AS path baseline comparison

Add expected path database that flags when observed path doesn't match historical patterns.

Implementation sketch:

```python
class PathValidator:
    def __init__(self):
        self.baseline_paths = {}  # prefix -> list of normal AS paths
    
    def validate_path(self, prefix, observed_path):
        expected = self.baseline_paths.get(prefix, [])
        if observed_path not in expected:
            return "ANOMALOUS"
        return "EXPECTED"
```

This would automatically generate "path anomaly" alerts without requiring defenders to manually compare paths.

### Feature request 3: Application-layer telemetry

Add HTTP, DNS, TLS telemetry showing protocol-specific impact of path changes.

Implementation sketch:

```python
class ApplicationTelemetry:
    def emit_http_timing(self, url, dns_ms, tls_ms, response_ms):
        # Break down where latency occurred
        # DNS: 5ms (normal) vs 15ms (via longer path)
        # TLS: 20ms (normal) vs 45ms (additional handshake hop)
```

This would show how subprefix intercept affects real services, not just routing metrics.

### Feature request 4: Traffic volume modeling

Show bandwidth consumption changing when traffic reroutes through attacker AS.

Implementation sketch:

```python
class BandwidthMonitor:
    def calculate_utilisation(self, routing_table):
        # Model where traffic flows given current routes
        # Generate interface utilisation metrics
        # Show unexpected increase on attacker-controlled links
```

This would make traffic interception visible in bandwidth graphs, not just latency metrics.

## References

- [Original operation: Subprefix intercept](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/subprefix_intercept)
- [Playbook 2: ROA scope expansion and validation environment mapping](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/2)
- [Simulator code: easy/subprefix_intercept](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/medium/subprefix_intercept)

This scenario demonstrates the hardest detection challenge in BGP security: attacks that don't break things, just make them slightly worse. The Scarlet Semaphore's operational technique (polite forwarding) is deliberately difficult to catch. The simulator preserves that difficulty whilst avoiding the illegality of actually intercepting traffic.

Improvements welcome. Live operations discouraged.
