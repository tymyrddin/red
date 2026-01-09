# Route leak escalating into an effective hijack

Cause large‑scale traffic misdirection or disruption by exploiting export policy failures in the BGP control plane.

## Phase 1: Getting into position (still not BGP abuse)

1. Operate or compromise an `AS` with multiple BGP relationships. Typical examples:
   * Small ISP
   * Hosting provider
   * Research network
   * Regional transit customer

2. The `AS` has at least two types of neighbours. This is important: route leaks require *multiple relationships*, not sophistication.
   * Upstream providers
   * Peers or customers

3. Routing policy is complex, outdated, or poorly understood. Common realities:
   * Copy‑pasted configs
   * “Temporary” exceptions
   * Staff turnover
   * Automation without guardrails

Nothing hostile yet. Just entropy.

## Phase 2: The BGP control‑plane attack (the leak)

4. Learn routes from one neighbour and export to another. This is the key failure:
   * Customer routes are exported to peers
   * Peer routes are exported to upstreams
   * Upstream routes are exported to other upstreams

From BGP’s point of view: `UPDATE` messages are valid; attributes look normal; no rules are violated. This is the route leak.

5. Leaked routes propagate beyond their intended scope
   * Prefixes appear in places they were never meant to reach
   * Policy assumptions upstream are broken
   * Trust boundaries collapse quietly

At this moment, the control plane has already failed.

## Phase 3: Escalation into an effective hijack

6. Leaked routes become attractive paths. Reasons include:
   * Shorter `AS_PATH`
   * Unexpected peer preference
   * Avoidance of congested transit links

7. Other networks select the leaked route. Functionally, this now behaves like a hijack, even though the origin AS is still correct and no prefix was forged.
   * Traffic shifts
   * Legitimate origin is bypassed
   * No origin change is required

8. Traffic impact becomes visible:
   * Latency spikes
   * Packet loss
   * Regional outages
   * “The Internet is slow” tickets

## Why this is hard to diagnose (teaching value)

* The leaked `AS` looks legitimate. It really learned the routes and announced them. Nothing appears spoofed.
* Blame is operationally awkward. Was it a mistake? Was it negligence? Was it abuse? Early response is often hesitant because nobody wants to accuse the wrong party.

This chain shows that:

* A route leak **is** a BGP control‑plane attack, even without intent
* Hijack‑like effects do not require false origins
* BGP failures often escalate, rather than start, catastrophically
* Control‑plane trust collapses faster than defenders expect

Or, put bluntly: The Internet does not distinguish between malice and misconfiguration. It routes both at line speed.

## Why attackers like this chain? 

Even if the initial leak is accidental, an attacker can:

Exploit the instability:
* Repeatedly re‑announce leaked routes
* Combine with other announcements
* Time announcements during incident response

Hide behind plausible deniability:
* “We are investigating”
* “Unexpected propagation”
* “Policy misinterpretation”

This is a gift to anyone who prefers cover over cleverness.

## Related 

- [BGP hijacking & route leaks](https://red.tymyrddin.dev/docs/in/network/roots/ip/bgp-hijacking.html) - General, IPv4 context
- [IPv4 prefix hijacking](https://red.tymyrddin.dev/docs/in/network/roots/bgp/prefix-hijack/?utm_source=chatgpt.com) - Specific mechanics
