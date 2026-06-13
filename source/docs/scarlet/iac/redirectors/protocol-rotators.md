# Protocol rotators

A single channel is a single point of failure. The moment a defender blocks the HTTPS beacon, a one-protocol
operation goes dark. A rotator treats transport as something disposable: when HTTPS stops answering, the beacon
falls back to DNS, then to a WebSocket, then to ICMP, and keeps a thread of life through whatever egress the
target has not thought to close.

The second benefit is quieter. Different protocols land on different sensors, and those sensors are rarely
correlated. A channel that spends most of its time on HTTPS and slips occasionally to DNS spreads its evidence
across two teams who may never compare notes.

## The transports, and what each costs

* HTTPS. The default, because it blends. High bandwidth, terminates cleanly on an [nginx](nginx-redirector.md) or
[CDN](cdn-fronting.md) hop, and is the protocol most likely to be inspected closely precisely because everyone
uses it.
* DNS, DoH, DoT. Egress filtering rarely closes name resolution, so DNS often survives where everything else is
blocked. The cost is bandwidth: it suits keepalives and small commands, not transfer. DoH and DoT also wrap the
queries in TLS, which folds this back into the [TLS mimicry](tls-mimicry.md) question.
* WebSocket. A long-lived, bidirectional channel that reads as ordinary application traffic, and survives proxies
that would break a raw socket. Comfortable to front behind a CDN that already speaks it.
* ICMP. No ports, and on many networks no monitoring, so it can carry a channel where nothing else gets out.
Hardened estates drop or rate-limit it, and tunnelled ICMP has a packet-size and timing signature that stands out
to anyone looking.

## Rotation logic

The redirector side is plumbing: a listener per transport, each relaying to the frontend. The rotation lives in
the implant, which walks a priority list, health-checks the current channel, and steps down when it stops
answering:

```yaml
transports:
  - kind: https
    url: https://www.<customdomain>.com/api/v2/
    jitter: 0.3
  - kind: doh
    resolver: https://<doh-host>/dns-query
    domain: c2.<otherdomain>.com
  - kind: websocket
    url: wss://<name>.workers.dev/socket
  - kind: icmp
    host: <frontend-ip>
health_check_interval: 90s
fallback_after_failures: 3
```

The raw TCP, UDP, and DNS hops sit naturally on [socat](socat.md); the HTTP-aware ones on
[nginx](nginx-redirector.md). Most modern C2 frameworks already support multiple listeners, so the
[backend](../backends/c2s.md) often does the heavy lifting and the redirector layer just exposes each transport on
its own burnable host, provisioned the same way as any other through
[Terraform or cloud-init](../automation/providers.md).

## Trade-offs

* Every transport is another thing to get wrong. A DNS responder that leaks the real frontend, an ICMP tunnel left
running on a host meant to be HTTPS-only: more channels means more chances to misconfigure one into a
beacon.
* The fallback channels are louder than the primary. DNS exfil is unremarkable to a shop that does not watch DNS
and a flare to one that does. ICMP that suddenly carries payload is the same.
* Rotation slows containment but does not stop it. A defender who maps the full transport set blocks them together
rather than one at a time, and the rotation that looked like resilience becomes a list of indicators to hunt.

## What the defender does with it

The useful signal is the mix, not the protocol. A host whose protocol baseline shifts, that starts resolving high
volumes of long, high-entropy subdomains, or that carries ICMP payloads it never carried before, draws attention
through anomaly rather than signature. DNS volume and entropy analysis catches the slow channel; per-host protocol
baselining catches the fallback the moment it fires. The rotator's strength is breadth, and breadth is also what
gives a patient analyst more than one thread to pull.
