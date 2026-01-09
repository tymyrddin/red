# Compromised customer → false‑origin prefix hijack

Redirect or disrupt traffic for a target IPv4 prefix by abusing trust in the BGP control plane.

## Phase 1: Getting into position

This phase matters because it explains why the later BGP behaviour is accepted.

1. Target a small or poorly secured customer `AS`.
   * Typical targets:
     * Small ISPs
     * Hosting providers
     * Enterprises with their own `AS`
   * Motivation: weaker operational security, weaker monitoring.

2. Gain control over routing configuration. This does *not* require router exploitation. Common paths:
   * Compromised customer portal credentials
   * Access to automation pipelines
   * Insider access
   * Inherited access after acquisition or contract change

3. Influence which prefixes the AS announces. The AS is legitimately allowed to send BGP updates to its upstream.

## Phase 2: The BGP control‑plane attack

4. The AS originates a prefix it does not own
   * The prefix belongs to another organisation
   * The origin AS is now wrong
   * From BGP’s perspective: this is a normal UPDATE

5. Upstream accepts the announcement. Why this happens:
   * Prefix‑lists are missing or outdated
   * Trust‑based customer relationship
   * No strict origin validation
   * “This customer has never caused problems before”

6. The route propagates further.
   * Other networks learn the false origin
   * Some select it as the best path
   * No alarms necessarily trigger

This is a textbook BGP control‑plane failure: the protocol is doing exactly what it was designed to do.

## Phase 3: Network‑wide effects

7. Traffic shifts towards the attacker‑controlled path. Depending on topology:
   * Partial traffic redirection
   * Regional impact
   * Full hijack

8. Impact can vary without changing the attack:
   * Blackholing (drop traffic)
   * Interception (forward selectively)
   * Instability (route flapping if corrected and re‑announced)

9. Detection is ambiguous:
   * Looks identical to a misconfiguration
   * Origin `AS` appears “legitimate”
   * Blame is unclear in early stages

This ambiguity is why these attacks last longer than people expect.

## Why this chain works so well (teaching value)

* No protocol violation occurred
* No exploit was used
* No packet payloads were touched
* Every step is operationally plausible
* Responsibility is diffuse and slow to converge

In other words: the attack succeeds because the control plane is built on trust, not proof.

This chain demonstrates that:

* BGP control‑plane attacks often start outside BGP
* The *attack itself* is a single, boring announcement
* Detection depends more on governance and monitoring than on clever tooling
* Intent and accident are indistinguishable at first glance

Which is precisely why this attack still works in 2026.

## Related 

- [BGP hijacking & route leaks](https://red.tymyrddin.dev/docs/in/network/roots/ip/bgp-hijacking.html) - General, IPv4 context
- [IPv4 prefix hijacking](https://red.tymyrddin.dev/docs/in/network/roots/bgp/prefix-hijack/?utm_source=chatgpt.com) - Specific mechanics

