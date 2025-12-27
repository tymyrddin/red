# The poisoned registry

## When the rules themselves start lying

This bench models a control‑plane failure that looks less like sabotage and more like bureaucracy quietly eating its own tail.

In Ankh‑Morpork terms, this is not intercepted mail, lost carts, or suspiciously rerouted pigeons. This is someone altering the Guild Registry itself. The book still balances. The stamps are still official. It is just that the wrong names are now considered legitimate.

This scenario exists to demonstrate what happens when **routing authority data changes**, not when packets are merely misdirected.

It is louder than a fat finger. It is slower than a subprefix intercept. And it is vastly more unsettling.

## What this simulation is and is not

This is a **demonstration scenario** for workshops and simulation/tabletop exercises.

It simulates:

* Changes in routing authority state
* Consequent BGP behaviour as observed by defenders
* Telemetry that defenders plausibly receive

It does not simulate:

* Real RIR authentication workflows
* Full RPKI repository mechanics
* Human deception, phishing, or intrusion chains
* Legal, organisational, or political fallout

Those live elsewhere. Here, we focus on **what the city sees**, not how the intruder got in.

## The signal

### Control plane versus data plane

Fat finger hijack and subprefix intercept operate on the data plane. Routes appear, disappear, or become more specific. Traffic goes the wrong way, but the rulebook remains intact.

This scenario operates on the control plane.

Instead of arguing about which route is best, the simulation changes what is considered **authorised**.

From the point of view of the Department of Silent Stability, this is worse. You are no longer asking “why did traffic move”. You are asking “why does the truth itself disagree with us”.

## Scenario overview

The simulator models a simple but dangerous sequence:

1. A previously valid routing authorisation becomes invalid or disappears
2. A competing authorisation appears
3. BGP announcements react accordingly
4. Monitoring systems observe contradictory but technically consistent signals

No single step is dramatic. The damage comes from how cleanly everything appears to be working.

## Scenario definition

The scenario definition below is **identical to the simulator source** and should be treated as canonical.

```yaml
id: roa-poisoning
description: >
  Control-plane manipulation where routing authorisation data changes,
  causing legitimate routes to become invalid and attacker routes to
  appear authorised.

timeline:
  - t: 0
    action: start

  - t: 30
    action: roa_change
    prefix: 203.0.113.0/24
    victim_as: 65001
    state: invalid
    note: Legitimate ROA removed or altered

  - t: 90
    action: roa_change
    prefix: 203.0.113.0/24
    attacker_as: 65004
    state: valid
    note: New ROA appears for attacker AS

  - t: 120
    action: announce
    prefix: 203.0.113.0/24
    attacker_as: 65004
    note: Attacker announcement now appears authorised

  - t: 240
    action: withdraw
    prefix: 203.0.113.0/24
    attacker_as: 65004
    note: Announcement withdrawn after demonstration window
```

Nothing here is accidental. The delays are deliberate. Control‑plane systems do not react instantly, and neither do humans.

## What defenders observe

From the outside, this looks deeply confusing.

* The victim’s route is rejected by some peers
* The attacker’s route is accepted by the same peers
* Validators report everything is functioning correctly
* No obvious misconfiguration is visible on routers

This is how trust failures look in practice. Quiet. Procedural. Polite.

## Lantern fuel

The simulator emits telemetry that reflects **observer‑side perception**, not internal attacker actions.

### RPKI state changes

Validators notice authorisation changes and report state transitions.

```json
{
  "event_type": "rpki.state_change",
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65001,
    "previous_state": "valid",
    "current_state": "invalid"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "roa_removed"
  }
}
```

Later, a new valid authorisation appears.

```json
{
  "event_type": "rpki.state_change",
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65004,
    "previous_state": "not_found",
    "current_state": "valid"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "roa_created"
  }
}
```

From the validator’s perspective, this is entirely correct behaviour.

### BGP announcements under changed authority

Once authorisation changes propagate, routing behaviour follows.

```json
{
  "event_type": "bgp.update",
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65004,
    "rpki_state": "valid"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "authorised_announcement"
  }
}
```

Meanwhile, the victim’s announcements may still exist, but are now rejected by enforcing peers.

```json
{
  "event_type": "bgp.reject",
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65001,
    "reason": "rpki_invalid"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "victim_rejected"
  }
}
```

Nothing is “broken”. The system is doing exactly what it was designed to do.

## Why this is unsettling

Unlike data‑plane incidents, this scenario creates **epistemic failure**.

Different tools tell different truths:

* Validators insist the attacker is legitimate
* Routers enforce those decisions
* Operators insist nothing changed on their routers
* Customers insist the service is down

All of them are correct.

This is why control‑plane incidents are slow to diagnose. You are debugging trust, not packets.

## Workshop use

This bench is designed to provoke discussion rather than panic.

* Which signal would you trust first
* How would you verify an authority change
* Who in your organisation is allowed to make such changes
* How quickly would you even notice

There are no trick answers. Only uncomfortable ones.

## The aftermath

When the announcement is withdrawn, services recover. No packets were harmed permanently.

But something else lingers.

Someone now has to answer:

* Why was the authorisation changed
* Who approved it
* Why did no alert fire
* And whether the system can be trusted again

In Ankh‑Morpork, this is where committees form.

