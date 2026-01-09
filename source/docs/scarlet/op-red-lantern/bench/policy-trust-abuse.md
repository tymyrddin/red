# Policy trust abuse → preferred‑path hijack

Redirect traffic by exploiting BGP route‑selection policy rather than breaking validation or forging origins. This chain works even when origin information is correct.

## Phase 1: Getting into position (legitimate, boring, essential)

1. Gain a legitimate BGP relationship. No deception is required. The relationship is contractually valid. Choose a:
   * Customer of an ISP
   * Peer at an Internet Exchange
   * Downstream of a regional transit provider

2. Learn upstream routing preferences. Operators rarely document this publicly, but behaviour reveals it quickly. This knowledge is often implicit:
   * Customers preferred over peers
   * Peers preferred over upstreams
   * Local preference outweighs `AS_PATH` length

## Phase 2: The BGP control‑plane attack

3. No origin fraud yet. Announce an allowed prefix:
   * The prefix may be legitimately originated by the attacker, or
   * It may be a prefix the attacker is authorised to announce on behalf of someone else.

4. Crafts route attributes to exploit policy. The `UPDATE` is valid. The attributes are allowed. Examples:
   * Announcement via a customer relationship
   * Attributes that trigger higher local preference
   * Placement that avoids de‑preferencing

5. Upstream selects the attacker route as best
   * Not because it is shorter
   * Not because it is more specific
   * But because policy says it is preferred

This is the control‑plane attack: deliberate manipulation of selection logic.

## Phase 3: Network‑wide effects

6. Traffic shifts predictably. From the outside, the network appears healthy.
   * Follows the policy‑preferred path
   * May bypass the intended transit
   * Often affects large volumes of traffic

7. The legitimate path still exists. There is no outage, no flapping, and no obvious breakage. This is a silent redirection.

## Why this is difficult to detect

* Everything is technically correct, the origin is valid, prefixes are authorised, and attributes are within policy. Monitoring tools that look for “bad” routes see nothing.
* Disputes become contractual, not technical. “You are abusing customer preference” or “We are using the service as sold”. Resolution is slow and political.

This chain demonstrates that:

* BGP security is not only about validation
* Policy is part of the attack surface
* Control‑plane attacks can be fully compliant with the protocol

Or, less diplomatically: If policy decides routes, policy can be weaponised.

## Why attackers like this chain?

* Low risk: no spoofing or obvious violation, and no smoking gun.
* High leverage as it exploits one of the strongest decision criteria and overrides otherwise well‑engineered routing.

## Related 

- [BGP hijacking & route leaks](https://red.tymyrddin.dev/docs/in/network/roots/ip/bgp-hijacking.html) - General, IPv4 context
- [IPv4 prefix hijacking](https://red.tymyrddin.dev/docs/in/network/roots/bgp/prefix-hijack/?utm_source=chatgpt.com) - Specific mechanics
