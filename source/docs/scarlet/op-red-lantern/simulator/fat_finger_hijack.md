# Fat finger hijack (simulator scenario)

## From live operation to safe simulation

[The original fat finger hijack](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack) was carried out by the Scarlet Semaphore against actual routing infrastructure. It caused real disruption. Services went unavailable. People noticed.

This was not ideal for anyone involved.

The Patrician, in his characteristic way of turning problems into opportunities, [engaged Purple Lantern Practice Ltd](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/patrician-engagement) to build a simulator. The Scarlet Semaphore was encouraged (strongly) to cease live operations and collaborate on translating their techniques into scenarios that could be safely repeated for training purposes.

This scenario is the result of that collaboration.

## What the simulator currently models

The live operation involved:
- Compromised router access (SSH to NOC infrastructure)
- BGP configuration changes via CLI
- Actual prefix announcements reaching global routing tables
- Real traffic disruption for 110 seconds
- Manual investigation and cleanup

The simulator models:
- BGP announcement telemetry (what monitoring would see)
- Router syslog entries (what logs would show)
- Prefix limit violations (detection opportunity)
- Traffic restoration (cleanup phase)

What's preserved: The detection challenge. The ambiguity about whether this is accident or attack. The brief window where defenders could notice prefix limit exceeded before the withdrawal.

What's simplified: No actual routing disruption. No real credential compromise required. Time is compressed from real-world (takes minutes to notice, coordinate response, execute) to simulation (completes in 2 minutes of simulated time).

## Scenario structure

```yaml
id: fat-finger-hijack
timeline:
  - t: 0    # Scenario begins
  - t: 10   # Exact-prefix announcement (misorigin)
  - t: 120  # Withdrawal after 110 seconds
```

The announcement at t=10 maps to [The Sequence section](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack#the-sequence) of the live operation: "BGP announcement of victim's exact prefix".

The withdrawal at t=120 maps to "Rapid withdrawal" from the operational documentation.

## Telemetry generation

From `telemetry.py`:

```python
bgp_gen.emit_update(
    prefix="203.0.113.0/24",
    as_path=[65002],
    origin_as=65002,
    next_hop="192.0.2.1",
    scenario={"name": "fat-finger-hijack", "attack_step": "misorigin"}
)
```

This generates what BGP route collectors would show. It doesn't execute actual BGP announcement (that would require AS ownership, BGP peering, and would disrupt real networks).

The `prefix_limit_exceeded` telemetry maps to [detection opportunity](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack#detection-in-practice): "Prefix limit violations might appear in logs". This is the signal defenders should catch.

## What defenders practice

Running this scenario trains analysts to:

Recognise exact-prefix misorigin patterns
BGP UPDATE showing unexpected AS originating known prefix. This looks exactly like [the signal description](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack#the-signal) from the operational documentation.

Distinguish accident from attack
Could be fat-finger (operator typo in config). Could be deliberately disguised attack. Could be automation failure. The telemetry doesn't label itself.

Notice prefix limit violations
If monitoring is configured, prefix limits exceeded indicates unusual announcement volume. This should trigger investigation even if brief.

Understand timing is critical
110-second window in scenario reflects reality: most fat-finger hijacks are noticed quickly and withdrawn. If you don't catch it in first 2 minutes, it's gone and you're analysing historical data.

## What's missing (simulator limitations)

### No RPKI integration yet

Live operation notes: "If victim has RPKI deployed, announcement would be marked INVALID."

Current simulator: RPKI validation events can be emitted via `event_bus.publish()` but aren't automatically generated from BGP announcements.

Workaround: Telemetry generators can emit RPKI validation results manually, but there's no validation engine checking announcements against ROAs.

### No traffic flow simulation

Live operation: "Traffic reroutes to attacker AS, services degrade."

Current simulator: Latency spike telemetry represents this abstractly, but there's no actual traffic flow calculation showing which packets would route where.

Workaround: `LatencyMetricsGenerator.emit()` creates plausible latency increase, suggesting traffic took longer path. Defenders must infer rerouting from latency change.

### No dynamic response to defender actions

Live operation: Defender actions (blocking announcement, contacting upstream) would terminate attack early.

Current simulator: Timeline runs to completion regardless of defender actions. It's a recording, not an interactive environment.

Workaround: Post-exercise discussion covers "at what point could you have acted to terminate this?"

## Running the scenario

```bash
# Without background noise (quiet, easier to spot)
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml

# With background noise (realistic, harder to spot)
python -m simulator.cli simulator/scenarios/easy/fat_finger_hijack/scenario.yaml --background
```

With background noise enabled, the BGP announcement gets lost in normal internet churn (0.5 updates/second by default). This models the detection challenge from [the operational notes](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack#detection-in-practice): "Single announcement among thousands of daily BGP updates."

## Suggestions for simulator improvements

### Feature request 1: RPKI validation engine

Add RPKI validation that automatically checks announcements against ROA database.

Implementation sketch:

```python
class RPKIValidator:
    def __init__(self):
        self.roas = {}  # prefix -> (origin_as, max_length)
    
    def validate(self, prefix, origin_as):
        # Check if ROA exists and covers this announcement
        # Return: VALID | INVALID | NOT_FOUND
```

This would allow scenarios to automatically generate RPKI validation state changes when BGP announcements occur, without manual telemetry generation for each.

### Feature request 2: Traffic flow modeling

Add simple traffic flow calculation showing which prefixes would route via which AS given current announcements.

Implementation sketch:

```python
class TrafficSimulator:
    def calculate_path(self, source, destination, routing_table):
        # Apply longest-prefix-match
        # Return selected AS path
        # Generate latency based on path length
```

This would make latency changes derivable from routing decisions rather than manually specified in telemetry.

### Feature request 3: Defender interaction

Allow defenders to take actions during scenario that affect outcome.

Implementation sketch:

```python
class DefenderActions:
    def block_announcement(self, prefix, as_number):
        # Remove from routing table
        # Emit log of defensive action
    
    def contact_upstream(self, peer_as):
        # Trigger peer response (withdrawal or filtering)
```

This would transform scenarios from recordings into interactive exercises where defender decisions matter.

### Feature request 4: Automated timeline scaling

Currently, timeline scaling from operational reality (minutes to hours) to simulation (seconds to minutes) is manual. Could be automated based on event dependencies.

Implementation sketch:

```python
def compress_timeline(events, target_duration):
    # Preserve relative timing and causal relationships
    # Scale absolute times to fit target duration
    # Maintain detection windows proportionally
```

This would make it easier to create scenarios from operational timelines without manual time adjustment.

## References

- [Original operation: Fat finger hijack](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/fat_finger_hijack)
- [Playbook 1: Registry reconnaissance and initial ROA creation](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/playbooks/1)
- [Simulator code: easy/fat_finger_hijack](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/easy/fat_finger_hijack)

This scenario represents compromise between operational reality (Scarlet's live attack) and training safety (Purple Lantern's simulator constraints). It's not perfect. It's what's currently possible. Improvements are welcome, preferably via pull request rather than unauthorised routing infrastructure modification.
