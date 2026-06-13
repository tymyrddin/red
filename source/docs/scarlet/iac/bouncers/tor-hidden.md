# Tor hidden services

The [WireGuard mesh](wireguard-mesh.md) hides the route but still hangs an IP off every hop, and an IP is a thing a
defender can block, subpoena, or seize. An onion service removes the address from the equation entirely. The
frontend binds to localhost, Tor publishes a service descriptor instead of a route, and the only handle the world
gets is a key. There is nothing to block, because there is nothing to point at.

This is the opsec-heavy end of the section. It trades reach and speed for the property that a burned host reveals
no upstream address, because the upstream never had one on the wire.

## The shape

```text
implant ── Tor ──> rendezvous ──> onion service (frontend, localhost-bound)
```

The implant carries a Tor client and dials a v3 onion address. Tor's own circuit handles reachability through
introduction and rendezvous points, so neither end advertises an IP and no exit node is involved: traffic to an
onion service stays inside the network end to end. The frontend never opens an inbound port to the internet at
all.

## Publishing the service

On the frontend, `torrc`:

```text
HiddenServiceDir /var/lib/tor/c2/
HiddenServicePort 443 127.0.0.1:8443
```

Tor writes the `.onion` hostname and the service keys into `HiddenServiceDir` on first start. The C2 listener
binds to `127.0.0.1:8443` and is reachable only through the published address. The keys in that directory are the
identity of the service: back them up to the encrypted state volume, because losing them loses the address, and
leaking them lets someone else answer to it.

## Trade-offs

* Tor in an enterprise is a flare. Almost no legitimate corporate egress carries it, so a plain Tor connection from
inside the target can be more conspicuous than the C2 it protects. A pluggable transport (obfs4, meek, snowflake)
disguises the connection as something duller, at the cost of a bridge to maintain and more moving parts in the
implant.
* The implant needs a Tor client, which is footprint: a process, libraries, or an embedded library that an
endpoint product can fingerprint.
* Latency and reliability are worse than a direct tunnel. Circuits drop and rebuild, and a beacon that already
threads a [protocol rotator](../redirectors/protocol-rotators.md) on top of this can feel every second of it.
* Location hiding holds against blocking and seizure, not against a global passive observer correlating traffic at
both ends. That adversary is rare in most engagements, but it is the one the design does not defeat.

## What the defender does with it

The detection rarely needs the payload. Tor's published relay and guard lists are downloadable, so an egress
connection to a known guard is a single-lookup catch. Where pluggable transports hide the destination, the focus
shifts to the anomaly: a host inside an estate that has no business speaking Tor, an obfs4 flow that does not match
the application it claims to be, a process with Tor libraries on a machine that has no business carrying them. The onion
service keeps the upstream invisible and leaves the client's choice to use Tor at all sitting in the egress logs,
which is usually the louder signal.
