# ROA poisoning (simulator scenario)

## From control-plane compromise to contained simulation

[The original ROA poisoning operation](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning) was 
the Scarlet Semaphore's most sophisticated work. It targeted RPKI infrastructure itself, turning the validation 
system into a weapon. It was to demonstrate that deploying RPKI doesn't solve BGP security if the RPKI system can be 
compromised.

It was also [the operation that got the most attention from parties who preferred routing infrastructure remain stable](../rose/patrician-red-line.md).

The [Patrician's intervention](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/patrician-engagement) was direct. 
We, the Semaphore were given a choice between windows and collaboration. We chose collaboration. This scenario is the 
sanitised, simulator-safe version of our control-plane attack techniques.

## What the simulator currently models

The live operation involved:

- Credential compromise (RIR portal phishing)
- ROA manipulation (delete victim's, create attacker's)
- BGP policy modification (unauthorised config changes)
- RPKI validation state flip (legitimate routes marked invalid)
- Blackhole community tagging (traffic deliberately dropped)
- Route flapping for noise (cover operational activity)
- Multi-week persistent access

The simulator models:

- Suspicious authentication (unusual login location)
- ROA deletion events (audit log entries)
- RPKI state changes (validation flip from valid to not_found)
- Policy commit telemetry (unauthorised Git commits)
- BGP announcements with manipulated ROAs
- Route rejection due to RPKI invalid state
- Blackhole community detection
- Coordinated route flapping patterns

What's preserved: The control-plane attack structure. The detection challenges (events spread across multiple systems, 
correlation required). The operational cover techniques (noise generation, legitimate-looking changes).

What's simplified: No actual credential compromise. No real RPKI infrastructure touched. No multi-week timeline. 
Compressed to 10 minutes simulated time from what was weeks of operational activity.

## Scenario structure

```yaml
id: roa-poisoning
timeline:
  - t: 0     # Scenario start
  - t: 10    # Baseline: RPKI valid
  - t: 120   # Suspicious login (TOR exit, unusual location)
  - t: 240   # ROA deleted
  - t: 245   # RPKI state flip (valid → not_found)
  - t: 300   # Policy commit (BGP config modification)
  - t: 360   # Attacker announces with their ROA
  - t: 365   # Victim's route rejected (RPKI invalid)
  - t: 370   # Blackhole community tagged
  - t: 400   # Coordinated flapping (noise generation)
  - t: 600   # ROA restored (cleanup)
  - t: 605   # Logout
```

This maps to [The Sequence](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#the-sequence) 
from operational documentation, heavily time-compressed:

- Real operation: Initial access days/weeks before ROA manipulation
- Simulator: t=120 (2 minutes in)
- Real operation: ROA propagation 30-90 minutes
- Simulator: 5 seconds (t=240 to t=245)
- Real operation: Sustained compromise days/weeks
- Simulator: 10 minutes total

Time compression is necessary for simulation/tabletop exercise. Causal relationships preserved.

## Telemetry generation

From `telemetry.py`:

Suspicious authentication:

```python
event_bus.publish({
    "event_type": "access.login",
    "attributes": {
        "user": "admin_backup",
        "source_ip": "185.220.101.45",  # TOR exit node
        "location": "RU",
        "system": "routing_portal",
        "suspicious": True,
        "reason": "unusual_location"
    }
})
```

This is the initial access indicator. From 
[operational documentation](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#initial-access-vectors): 
"Compromised credentials, often via phishing. Login from unexpected location/IP."

ROA manipulation:

```python
syslog_gen.emit(
    message="ROA for 203.0.113.0/24 removed by admin_backup",
    severity="warning",
    subsystem="rpki"
)
```

This is the control-plane attack. From operational notes: "Deletion of legitimate ROA is the moment where validation 
infrastructure is compromised."

RPKI state flip:

```python
syslog_gen.emit(
    message="RPKI state for 203.0.113.0/24 flipped from valid to not_found",
    severity="notice",
    subsystem="rpki"
)
```

This is validators noticing ROA disappeared. Propagation delay (t=240 to t=245) models real RPKI propagation timing.

Blackhole community:

```python
syslog_gen.emit(
    message="Blackhole community 65535:666 detected on 203.0.113.0/24",
    severity="critical",
    subsystem="bgp"
)
```

This is the weaponisation phase. From [operational docs](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#community-tag-abuse): "Blackhole community causes networks to drop all traffic for prefix. DDoS mitigation infrastructure turns against victim."

## What defenders practice

Running this scenario could train analysts to:

- Recognise control-plane vs data-plane attacks: This isn't forged BGP announcements. This is manipulation of validation infrastructure. From [the signal section](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#the-signal): "Most BGP incidents operate on data plane. This operates on control plane. Authority itself is subverted."
- Correlate across multiple systems: Authentication logs (t=120), RPKI audit logs (t=240), BGP monitoring (t=360), policy repos (t=300). Events span 4 different systems. Most organisations don't correlate these.
- Detect audit log anomalies: ROA deletion from unusual source. Most organisations collect RPKI audit logs but don't actively monitor them. This is [detection gap documented](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#expected-telemetry): "Logs exist but aren't operationalised."
- Understand noise as operational cover: Route flapping at t=400 is deliberate. From operational docs: "Noise generation masks specific malicious changes among general instability." Defenders must filter signal from noise.
- Investigate authorisation for RPKI changes: Was `admin_backup` supposed to delete that ROA? Who approved? From where? These are forensic questions requiring organisational context, not just log analysis.

## What's missing (simulator limitations)

### No actual credential compromise simulation

Live operation: "Phishing campaign targeting NOC personnel. Credential harvesting via fake RIPE portal."

Current simulator: Suspicious login appears at t=120 but there's no preceding phishing simulation. No email telemetry showing phishing attempt. No user clicking suspicious link.

Workaround: Authentication event has `suspicious: True` flag. Defenders must infer credential compromise occurred, but don't see the compromise mechanism.

### No RPKI validation engine

Live operation: "Validators polling repositories, discovering ROA deletion, updating validation state, routers querying validators, updating routing decisions."

Current simulator: RPKI state change manually emitted at t=245. There's no actual validation engine checking announcements against ROA database.

Workaround: Telemetry shows state changed. Defenders must understand what this means (victim's routes now invalid), but don't see validation mechanism working.

### No policy change impact modeling

Live operation: "BGP policy modification at t=300 changed peer filters, allowing attacker announcements through that should have been filtered."

Current simulator: Policy commit event emitted, but no model of what that policy change actually did to routing behaviour.

Workaround: Telemetry shows config change occurred. Defenders must infer impact from subsequent events (attacker announcement accepted).

### No sustained access modeling

Live operation: "Attacker maintained access for weeks. Multiple logins, configuration queries, careful operational security."

Current simulator: Single login at t=120, logout at t=605. Real operation had many sessions over extended time.

Workaround: Compressed timeline represents multi-week operation in 10 minutes. Single login/logout pair represents multiple access sessions.

### No attribution forensics

Live operation: "Post-incident attribution required correlating TOR exit nodes, timing patterns, operational techniques, possibly identifying individuals."

Current simulator: Logout at t=605 and scenario ends. No post-incident phase where defenders try to figure out who did it.

Workaround: Post-exercise discussion covers attribution, but simulator doesn't model investigative process.

## Running the scenario

```bash
# Standard run
python -m simulator.cli simulator/scenarios/advanced/roa_poisoning/scenario.yaml

# With background noise (much harder, realistic)
python -m simulator.cli simulator/scenarios/advanced/roa_poisoning/scenario.yaml --background

# Training mode (includes debug markers)
python -m simulator.cli simulator/scenarios/advanced/roa_poisoning/scenario.yaml --mode training

# Export for analysis
python -m simulator.cli simulator/scenarios/advanced/roa_poisoning/scenario.yaml \
  --output json --json-file roa_poisoning_telemetry.json
```

With `--background`, the control-plane attack events (login, ROA deletion, policy change) get lost in normal operational noise. Authentication systems see hundreds of logins daily. RPKI audit logs accumulate entries nobody reads. Git repos have constant commits. This models [detection reality](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning#detection-in-practice): "Signal exists but is not monitored."

With `--mode training`, events include `scenario.attack_step` field marking which phase of attack each event belongs to. This helps facilitators but should not be shown to defenders during exercise.

## Suggestions for simulator improvements

### Feature request 1: Phishing simulation component

Add email telemetry showing phishing attempt preceding credential compromise.

Implementation sketch:
```python
class PhishingSimulator:
    def generate_campaign(self, targets, template):
        # Generate email events showing phishing delivery
        # Some recipients click, some don't
        # Clicked recipients later show up in auth logs
```

This would show the full attack chain from initial access vector through exploitation.

### Feature request 2: RPKI validation engine with ROA database

Add actual validation logic checking BGP announcements against ROA database.

Implementation sketch:

```python
class RPKIValidator:
    def __init__(self):
        self.roas = ROADatabase()
    
    def validate_announcement(self, prefix, origin_as):
        roa = self.roas.lookup(prefix)
        if not roa:
            return "NOT_FOUND"
        if roa.origin_as != origin_as:
            return "INVALID"
        if prefix_length > roa.max_length:
            return "INVALID"
        return "VALID"
```

This would automatically generate validation state changes when ROAs are modified, without manual telemetry generation.

### Feature request 3: Policy impact modeling

Model what BGP policy changes actually do to routing decisions.

Implementation sketch:

```python
class PolicyEngine:
    def apply_policy(self, announcement, policy_config):
        # Check if announcement matches filters
        # Apply accept/reject rules
        # Return routing decision
        # Generate telemetry showing what was allowed/blocked
```

This would show consequences of policy modifications, not just that config changed.

### Feature request 4: Multi-week timeline support

Currently scenarios run minutes. Control-plane attacks in reality take weeks.

Implementation sketch:

```python
class ExtendedTimeline:
    def compress_timeline(self, operational_timeline, target_duration):
        # Identify critical decision points
        # Compress operational gaps (waiting, reconnaissance)
        # Preserve detection windows proportionally
        # Generate periodic "nothing happening" telemetry for sustained phases
```

This would allow more realistic modeling of sustained access without requiring hour-long simulation/tabletop exercises.

### Feature request 5: Post-incident forensics phase

Add timeline phase after attack showing investigation, attribution attempts, recovery.

Implementation sketch:

```python
class ForensicsSimulator:
    def generate_investigation_telemetry(self, attack_telemetry):
        # Generate analyst queries
        # Show correlation being discovered
        # Model attribution challenges (TOR, false flags)
        # Generate recovery actions (ROA restoration, credential reset)
```

This would train incident response and forensic analysis, not just detection.

### Feature request 6: Defender action system

Allow defenders to take actions during scenario that affect outcomes.

Implementation sketch:

```python
class DefenderActions:
    def reset_credentials(self, account):
        # Lock out attacker
        # Subsequent attacker actions fail
        # Generate defensive telemetry
    
    def restore_roa(self, prefix, origin_as):
        # Undo ROA manipulation
        # Validation state flips back
        # Attacker announcements become invalid
```

This would make scenarios interactive rather than passive observation.

## References

- [Original operation: ROA poisoning](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/roa_poisoning)
- [Playbook 3: Prefix hijacking with RPKI validation cover](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/3)
- [Control-plane vs data-plane distinction](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/control-vs-data-plane)
- [Simulator code: advanced/roa_poisoning](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/advanced/roa_poisoning)

This scenario represents the most sophisticated attack the Scarlet Semaphore executed before the Patrician's intervention. It demonstrates that RPKI deployment alone is insufficient if the RPKI infrastructure itself can be compromised. The simulator preserves the detection challenges whilst avoiding the legal consequences of actually compromising routing infrastructure.

The Semaphore's cooperation in translating their techniques into training scenarios was not entirely voluntary. The alternative options presented by the Patrician were considerably less appealing. But the result is valuable: defenders can now practice detecting control-plane attacks without anyone actually attacking control planes.

Collaboration achieved. Future live operations discouraged with extreme prejudice.
