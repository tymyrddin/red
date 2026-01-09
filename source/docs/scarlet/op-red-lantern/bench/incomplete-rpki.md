# Incomplete RPKI deployment → opportunistic prefix hijack

Hijack traffic for a target IPv4 prefix by exploiting gaps and inconsistencies in RPKI deployment and enforcement. 
This is not a crypto attack. It is a governance and coverage attack.

## Phase 1: Reconnaissance (still not BGP abuse)

1. Survey RPKI coverage. This information is public and easy to obtain.
   * Checks which prefixes have ROAs
   * Checks maximum prefix lengths
   * Note which regions enforce validation strictly

2. Selects a viable target. Nothing illegal. Nothing noisy. Characteristics:
   * No ROA at all, or
   * ROA exists but only for a less‑specific prefix
   * Inconsistent enforcement by transit providers

## Phase 2: The BGP control‑plane attack

3. Announce the target IPv4 prefix. From the control plane’s perspective the `UPDATE` is well‑formed and validation result is “not found”, not “invalid”.
   * Prefix is unprotected or ambiguously protected
   * Origin `AS` is unauthorised but not cryptographically blocked

4. Networks without strict validation accept the route
   * Many networks still do
   * Some only drop “invalid”, not “unknown”
   * Some ignore validation entirely

This is the critical control‑plane failure: *acceptance by policy*.

## Phase 3: Partial but persistent impact

5. Hijack succeeds unevenly. This unevenness makes the incident harder to reason about.
   * Some regions follow the attacker route
   * Others follow the legitimate one
   * Behaviour differs by upstream

6. The attacker does not need global success. The attack can persist quietly.
   * Even partial traffic capture may be enough
   * Detection thresholds are often tuned for outages, not splits

## Phase 4: Defenders struggle

7. No cryptographic violation occurred
   * Nothing is marked “invalid”
   * Alarms do not fire automatically

8. Operators disagree on severity
   * “Our part of the Internet looks fine”
   * “Must be someone else’s problem”

Coordination drags. Time passes.

## Why this chain works so well (educational value)

* The attacker exploits uneven standards adoption: Security is only as strong as the weakest enforcing `AS`; partial deployment creates grey zones
* Blame is diffuse: The victim did not publish a ROA, the attacker exploited that absence, and the network accepted what policy allowed. Everyone is technically “within spec”.

This chain shows that:

* RPKI reduces risk, it does not eliminate it
* “not found” is not the same as “safe”
* Control‑plane security fails at boundaries, not at cores

Or, put bluntly: A standard that is not universally enforced is a suggestion, not a shield.

## Related 

- [BGP hijacking & route leaks](https://red.tymyrddin.dev/docs/in/network/roots/ip/bgp-hijacking.html) - General, IPv4 context
- [IPv4 prefix hijacking](https://red.tymyrddin.dev/docs/in/network/roots/bgp/prefix-hijack/?utm_source=chatgpt.com) - Specific mechanics
