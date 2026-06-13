# WireGuard mesh

The other pages in this section deal with where a bounce server comes from: who to pay, and how to pay them without
signing the work. This one is about what to do with three of them once they exist. A single bouncer is a couch to
crash on. A mesh is the whole network of couches, each one only knowing the address of the next, so that pulling
the thread at any one of them unravels a single hop rather than the route.

The old way to chain bouncers was a stack of SSH tunnels or socat forwards, which meant TCP inside TCP, brittle
sessions, and a login on every box. WireGuard collapses that into a private overlay: each host holds a key, peers
that present the right key get a route, and everything else is met with silence. The silence is the useful part.
A WireGuard endpoint does not answer unauthenticated packets at all, so a port scan of the bouncer finds nothing
listening where the tunnel is.

## What the mesh buys

* One UDP port and a small static config per host, rather than a live session to babysit.
* Peers identified by public key, not passwords, so a leaked host yields ciphertext and its immediate neighbours,
not credentials to the rest.
* `AllowedIPs` scoping that limits what each peer is permitted to route, so a mid-chain node cannot reach past the
slice of the overlay it was given.
* Tear-down by subtraction. When a host burns, the survivors drop the dead peer and the route reforms around it.

## Topology

A full mesh, where every node peers with every other, is rarely what an operation wants. It is convenient and it
means any seized host reveals the entire roster. A relay chain is the quieter shape: the redirector-facing edge
peers only with the next hop, that hop peers only with the one after, and the frontend sits at the far end. Each
node knows its two neighbours and nothing else, so a forensic team working inwards from a burned edge recovers one
link at a time.

## One hop

A point-to-point hop on the chain, `/etc/wireguard/wg0.conf` on the edge node:

```ini
[Interface]
PrivateKey = <edge-private-key>
Address    = 10.8.0.2/32
ListenPort = 51820

[Peer]
# the next hop inward
PublicKey           = <nexthop-public-key>
AllowedIPs          = 10.8.0.3/32
Endpoint            = <nexthop-ip>:51820
PersistentKeepalive = 25
```

The next hop carries the mirror of this, plus its own peer pointing further in. `AllowedIPs` is doing the access
control: this edge can reach `10.8.0.3` and nowhere else on the overlay, so even with the key it cannot wander the
rest of the chain.

## Keys and ephemerality

Generate the keys on the host at first boot, never in a repo. The
[cloud-init pattern](../automation/providers.md) that already provisions the bouncer can mint the keypair and write
the config in the same `runcmd` pass:

```yaml
runcmd:
  - umask 077; wg genkey | tee /etc/wireguard/priv | wg pubkey > /etc/wireguard/pub
  - systemctl enable --now wg-quick@wg0
```

The private key lives and dies with the host. When the edge is rotated, its key is gone, the next hop drops a peer
that will never come back, and a freshly provisioned edge joins under a new key and a new address. That is the
[anonymous-payment](providers.md) hosts' single real advantage put to work: cheap, disposable, and quick to
replace.

## Trade-offs

* WireGuard is recognisable. The handshake has a distinct shape, the default `51820/udp` is a tell, and the
`PersistentKeepalive` heartbeat is a metronome that timing analysis reads easily. Moving the port helps a little;
the handshake fingerprint travels regardless.
* A mesh wants its nodes up long enough to be worth building, which pulls against the rotate-everything-hourly
instinct. The chain is more durable than a lone redirector and slower to throw away. Pick which property the
operation actually needs.
* The overlay hides routing from a network observer, not from the hosts. A seized mid node still exposes the IPs
of the neighbours it peers with, which is the whole reason for keeping each node's view to two hops.
* More hops means more latency, and a C2 beacon already living behind a [CDN](../redirectors/cdn-fronting.md) and a
[protocol rotator](../redirectors/protocol-rotators.md) can accumulate enough delay to change its own timing
signature.

## What the defender does with it

WireGuard to a cloud VPS is not suspicious on its own; plenty of legitimate remote access looks identical. The
signal is the company it keeps. A handshake to a host that also serves a thin cover site, a keepalive heartbeat
steady enough to set a clock by, or netflow that lines up a chain of UDP relays between an edge the target talked
to and a frontend it never saw: each of these reads as structure rather than content. The mesh keeps the payload
private and leaves the shape of the route on the wire, which is where a patient analyst tends to look.
