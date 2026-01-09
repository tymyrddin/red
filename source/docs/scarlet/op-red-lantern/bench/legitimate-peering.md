# Legitimate peering → more‑specific prefix hijack

Attract traffic for a target IPv4 prefix by exploiting longest‑prefix match in the BGP control plane.

## Phase 1: Getting into position (administrative, not technical)

1. Acquire a legitimate BGP peering. No deception is required here. Play by the rules. Common routes:
   * Internet Exchange membership
   * Reseller or transit contract
   * Lab or research network access

2. Peering filters are permissive or minimal. This is where trust quietly enters the room. Typical assumptions:
   * “They will only announce what they should”
   * Prefix‑lists are outdated
   * Automation trusts IRR data blindly

## Phase 2: The BGP control‑plane attack

3. Announce a more‑specific IPv4 prefix. 
   * Legitimate owner announces, for example, a `/20`
   * Announce a contained `/24`

This announcement is syntactically valid, passes basic filtering, and does not contradict origin validation if no ROA exists for the `/24`

4. Longest‑prefix match overrides everything else. This is not a bug. This is how routing works.
   * `AS_PATH` length does not matter
   * Local preference often does not matter
   * Routing policy bows to specificity

## Phase 3: Network‑wide effects

5. Traffic shifts towards us
   * Only traffic for the more‑specific range is affected
   * Impact may be partial or regional
   * The rest of the prefix behaves normally

This makes the attack quieter, harder to spot, easier to deny.

6. No outage is required:
   * Packets may still reach their destination
   * Services appear “up but slow”
   * Users complain vaguely

Operational hell, not dramatic failure.

## Phase 4: Why detection lags

7. The legitimate origin is still visible
   * Monitoring sees both routes
   * Nothing looks “down”

8. The attack looks like traffic engineering
   * More‑specifics are used legitimately
   * IX participants do this every day

Defenders hesitate because the behaviour is familiar.

## Why this chain is so effective

* Minimal attacker effort: one UPDATE, one prefix, no timing tricks
* Maximum protocol leverage: relies on the single strongest rule in IP routing; overrides decades of policy nuance.

This chain demonstrates that:

* The most powerful BGP attacks are not subtle
* Longest‑prefix match is absolute
* Trust plus specificity beats good intentions every time

Or, less politely: You can have perfect policies, monitoring, and paperwork. A /24 will still ruin your afternoon.

## Related 

- [BGP hijacking & route leaks](https://red.tymyrddin.dev/docs/in/network/roots/ip/bgp-hijacking.html) - General, IPv4 context
- [IPv4 prefix hijacking](https://red.tymyrddin.dev/docs/in/network/roots/bgp/prefix-hijack/?utm_source=chatgpt.com) - Specific mechanics
