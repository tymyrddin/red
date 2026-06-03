# NTP assessment: time is infrastructure too

*Or: How Ponder Discovered That Nobody Thinks About the Clock Until It Lies*

## The overlooked service

NTP rarely appears on the mental list of protocols to assess in an OT environment. It does not speak Modbus.
It cannot write to a PLC register. It does not appear on lists of industrial protocols. It sits in the
background, small and quiet, synchronising clocks nobody audits.

Which is, of course, why it is interesting.

Time underpins several things that matter for security: log timestamps used in sequence-of-events analysis,
TLS certificate validity windows, and the replay protection intervals in newer OT protocols that have any replay
protection at all. Shift the clock on a machine and its logs begin to lie about when things happened. Shift it
far enough and its TLS certificates appear expired. Shift it precisely and replay-protection windows become
exploitable.

None of this is straightforward. NTP manipulation is usually a precondition for something else, not an attack
in its own right. It is the kind of finding that matters more in a sophisticated, multi-stage engagement than in
a quick reconnaissance exercise.

## The UU P&L clock

The Guild Quarter DMZ includes `guild-clock` at 10.10.5.30, providing NTP to DMZ hosts. It runs without
authentication: any client can query it, any host reaching UDP port 123 can receive responses.

The first step is passive and leaves no mark:

```bash
ntpq -p 10.10.5.30
```

This returns the server's reference clock, its upstream peers, and the offset and jitter values for each. No
credentials required. The output is reconnaissance: the peer list reveals which DMZ hosts synchronise from
this server, which in turn defines the spread of any clock manipulation.

```bash
ntpq -c sysinfo 10.10.5.30
```

This returns server configuration and stratum information, also unauthenticated.

Security implication: server topology and client list are enumerable by any host on the network, at no cost and
with no authentication.

## What an unauthenticated NTP server enables

Injecting false NTP responses requires either control of the server itself (via a separate compromise) or a
network position between the server and its clients. From the internet zone, neither is immediately available.
From a foothold in the DMZ, after compromising `contractors-gate` for instance, both become feasible.

If an attacker shifts the system clocks of DMZ hosts forward by 30 minutes:

- TLS certificates with narrow validity windows appear not-yet-valid or already expired, potentially disrupting TLS-dependent services and generating errors that obscure the actual incident
- Log timestamps become misaligned with actual event times; sequence-of-events reconstruction after an incident depends on timestamps that now reflect a clock that was wrong
- Protocols using time-based replay protection become vulnerable to replayed messages within the shifted window

The practical impact varies by environment. Where log correlation across zones is the primary forensic tool,
reliable timestamps are load-bearing. Where nobody correlates logs anyway, shifting the clock is theatrical.

## What safe assessment involves

Passive querying with `ntpq` is always appropriate in scope. It leaves nothing behind and reveals topology.

Active manipulation, whether via NTP response injection, clock stepping through a compromised server, or
ARP-based interception, has real consequences for the hosts trusting the server. Testing these techniques on
the simulator is appropriate; testing on production infrastructure without explicit scope and operational
sign-off is not.

At UU P&L, assessment covered:

- Confirming the server responds without authentication: one `ntpq` command
- Documenting which hosts appear in the peer list: passive intelligence
- Noting the absence of NTP authentication keys: a finding
- Recording which systems depend on guild-clock for accurate timestamps: the risk

## What the testing revealed

Unauthenticated NTP is the norm, not the exception, in operational technology environments. The more important
observation is what the DMZ hosts do with the time they receive. If they feed it into process historians,
sequence-of-events logs, or security monitoring, the NTP server becomes a single point of failure for the
reliability of those records.

A single unauthenticated NTP server providing time to the DMZ compounds every other risk that depends on
accurate logging. It rarely appears in a CVSS score. It has no port number that stands out on a scan. It is
the kind of finding the Bursar files under "medium, address later" and the Director of Operations does not
remember being told about.

It becomes significant precisely when something else has already gone wrong.

Ponder's assessment note: "Time manipulation is the finding that looks unimpressive until forensics fails.
A historian showing normal operation during a period when the turbine was physically stopped is one kind of
problem. A historian showing normal operation during that period with timestamps that cannot be trusted is a
different kind, and a harder one to recover from. The clock was the thing nobody checked."

Further reading:

- [Time manipulation runbook](https://github.com/ninabarzh/ics-access-simlab/tree/main/docs/time-manipulation.md): NTP enumeration and manipulation techniques in the simulator
- [guild-clock README](https://github.com/ninabarzh/ics-access-simlab/tree/main/zones/dmz/components/guild-clock/README.md): server configuration and vulnerability notes