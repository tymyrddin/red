# Attack spectrum

These five chains are the Scarlet Semaphore's stock in trade: short, opportunist to resourced, never the
patient work of a state. They still run a spectrum, from a single announcement anyone holding a session can
make in minutes to a relationship abused over days. Reading down the table, who can afford the move and what
the redirected traffic is for both shift.

| Chain                                                                | Actor and timescale        | Objective                                  |
|----------------------------------------------------------------------|----------------------------|--------------------------------------------|
| [False-origin prefix hijack](runbooks/false‑origin-prefix-hijack.md) | opportunist, minutes       | seize or drop a prefix                     |
| [Incomplete-RPKI opportunistic hijack](runbooks/incomplete-rpki.md)  | opportunist, hours         | take unsigned or unenforced space          |
| [Legitimate-peering more-specific](runbooks/legitimate-peering.md)   | resourced, hours           | attract a slice of a block                 |
| [Route leak to effective hijack](runbooks/route-leak-hijack.md)      | resourced, minutes to days | redirect down a path no one is entitled to |
| [Policy-trust abuse](runbooks/policy-trust-abuse.md)                 | resourced, days            | win traffic on preference alone            |

Two notes follow. These five reproduce cleanly in a lab: mechanical moves on fixed BGP rules, the same every
time. And the defence is crisp, a ROA and an enforcing upstream settle most of them, with the fuller view in
the blue notes on [inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/).

The patient, state-scale campaigns are a different country. The
[Fungolia exercises](https://red.tymyrddin.dev/docs/earthworks/fungusfiber/) take up interception, selective
degradation, narrative disruption and years-long positioning, where there is no single fix and the answer is
posture rather than a filter.
