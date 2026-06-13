# IPv6 rotation

IP blocking is a blocking operation. A defender takes the address the beacon came from, adds it to a list, and
the channel goes quiet. An IPv6 /64 prefix contains 2^64 addresses. A /48, which some providers hand out as
standard, contains 2^80. Blocking individual addresses from a prefix that size is a treadmill; blocking the whole
prefix is the only meaningful response, and that often takes longer for a defender to reach than burning through
the addresses does for the operator.

Most VPS providers that assign IPv6 at all assign at least a /64. Hetzner gives a /64 per server by default;
others assign /48 or larger on request. The prefix is routed to the host. What lives inside it is the operator's
choice.

## Binding to arbitrary addresses in the prefix

The kernel routes the entire prefix to the interface. Adding a specific address from it is enough to bind:

```bash
# Add one address to use immediately
ip -6 addr add 2001:db8:1:2::dead:beef/64 dev eth0

# Or add the whole prefix to loopback and let applications pick any address
ip -6 route add local 2001:db8:1:2::/64 dev lo
```

With the prefix on loopback, any process can bind to any address in it without a prior `ip addr add`. Linux
honours the bind even if the address is not listed on an interface, as long as the route is present.

## Rotating the source in nginx

When nginx makes the upstream connection to the [backend](../backends/c2s.md), it can source from a specific
address. Pair this with a short script that rewrites the config and reloads:

```nginx
upstream c2_backend {
    server 10.0.0.2:8443;
}

server {
    listen [::]:443 ssl;
    # ...

    location /api/v2/ {
        proxy_pass         https://c2_backend;
        proxy_bind         2001:db8:1:2::$rotation_var;   # set via map or Lua
    }
}
```

A simpler pattern: a wrapper that picks a random address, assigns it, updates the nginx `proxy_bind` directive,
and does a graceful reload. A systemd timer running every few minutes keeps the source rotating without
interrupting live connections:

```bash
#!/bin/bash
PREFIX="2001:db8:1:2"
SUFFIX=$(printf '%x:%x' $((RANDOM % 65536)) $((RANDOM % 65536)))
ADDR="${PREFIX}::${SUFFIX}"

ip -6 addr replace "${ADDR}/64" dev eth0
sed -i "s|proxy_bind .*;|proxy_bind ${ADDR};|" /etc/nginx/conf.d/redir.conf
nginx -s reload
```

## What this does and does not solve

Rotating through a /64 defeats per-address blocking and makes the source address useless as a stable indicator.
It does not change the destination the beacon reaches (the frontend's address stays fixed from the target's
perspective), so rotation is most useful at the redirector-to-frontend hop, where the frontend can draw on a
large prefix while the redirector the target sees stays on a separate burnable host.

It also does not affect TLS fingerprinting, timing, or the behavioural patterns that [TLS mimicry](../redirectors/tls-mimicry.md)
and [protocol rotation](../redirectors/protocol-rotators.md) address. IPv6 rotation is one layer; the address is
one indicator. A /64 worth of addresses still all terminate at the same autonomous system, which a defender with
BGP-level visibility reads as a single block.

## What the defender does with it

Per-address blocking gives way to prefix-level blocking once the rotation pattern is recognised. A defender who
notices repeated connections from the same /64 across different source addresses can block the whole prefix in a
single rule, which is a faster response than chasing individual IPs. The useful detection comes earlier: the
prefix itself appears in BGP as a route from one provider, and provider-level reputation lookups flag a /64 that
has never appeared in that network's traffic before the operation started.
