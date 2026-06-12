# Denial and disruption

Rendering a service unavailable, or worse, untrustworthy, without destroying it. The loud version
saturates or stops the service; the quieter version leaves it running and makes it lie. The second is
harder to attribute and can do more, because a dead service invites remediation while a lying one
invites confidence.

## Volumetric denial

Flooding a link or a service past its capacity is the oldest form and the least interesting, because
it announces itself. Amplification and reflection raise the ratio; a botnet raises the source count.
The strategic value is rarely the outage itself, more often the distraction it provides or the cost
it imposes while something quieter runs alongside it. Scrubbing lives upstream of the target, so a
defender who waits for the flood to reach their own edge has already lost the link.

## Service stop

Stopping a service can be cleaner than flooding it, and can pass for maintenance. Where an attacker
already holds the orchestration layer, a scheduler, or a valid token, a service can be stopped with
the system's own tooling and no exploit at all.

```bash
# stop a service with the platform's own controls (reads as administration)
systemctl stop <service>            # Linux
# Windows: Stop-Service, or disable through the management console
```

## Routing and signal manipulation

The subtle case. Traffic is not stopped but misdirected, delayed, or desynchronised, so the service
is delivered wrong rather than not at all. ARP and DNS poisoning redirect at the local and name
layers, route manipulation redirects at the path layer, and replay or desync breaks the ordering and
the proof of who sent what. Telemetry can be made to read healthy while the process underneath is
anything but, which buys time, because a room will argue over sensor faults while the damage accrues.

```bash
# local redirection (lab use): ARP spoof via bettercap
# bettercap -iface eth0 -eval "set arp.spoof.targets <victim>; arp.spoof on"
```

The advantage here is deniability. Each phase has an innocent reading available for free, a dropout
blamed on weather, a malformed header filed as a replication bug, and the innocent readings hold
until the pattern is too tidy to ignore. By then the slow burn has bought days.
