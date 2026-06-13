# Building your own eyes

Borrowed eyes are quick, and they are someone else's logs. A rig of your own is slower to stand up and
answers to nobody but you. None of the pieces below need a budget or a peering to start: the first one
needs a network connection and about ten lines of Python.

If you would rather not assemble it piece by piece, [huginn-and-muninn](https://github.com/tymyrddin/huginn-and-muninn)
is a small, local take on exactly this: a listening eye, a snapshot looking glass, an RPKI check and a
historical recall, mostly standard library. The rest of this page is on how the pieces work, so you can build
or extend your own.

## A listening eye, in ten lines

RIS Live is RIPE's public websocket of BGP updates seen across its collectors. Subscribe to a prefix, and it
streams every announcement and withdrawal touching it, as JSON, from vantages worldwide. You announce
nothing; you only listen.

```bash
pip install websocket-client
```

```python
import json, websocket

PREFIX = "203.0.113.0/24"
ws = websocket.create_connection("wss://ris-live.ripe.net/v1/ws/?client=eyes-demo")
ws.send(json.dumps({"type": "ris_subscribe",
                    "data": {"prefix": PREFIX, "moreSpecific": True}}))

while True:
    msg = json.loads(ws.recv())
    if msg["type"] != "ris_message":
        continue
    d = msg["data"]
    for ann in d.get("announcements", []):
        for pfx in ann["prefixes"]:
            print(d["timestamp"], "A", pfx, "path", d.get("path"), "seen by", d["peer"])
    for pfx in d.get("withdrawals", []):
        print(d["timestamp"], "W", pfx, "seen by", d["peer"])
```

Run it, announce a more-specific of the prefix from somewhere, and the line turns up here with your origin
at the end of the path. That is a working eye. If you would rather not write the loop, `pybgpstream` wraps
the same live and archived feeds behind one API:

```python
from pybgpstream import BGPStream
stream = BGPStream(project="ris-live", filter="prefix more 203.0.113.0/24")
for e in stream:
    print(e.time, e.type, e.fields.get("prefix"), e.fields.get("as-path"))
```

## A collector of your own

When a table serves better than a stream, run a speaker that holds a RIB you can query. GoBGP is the least
fuss. Point it at a neighbour you have (a route server, a tolerant peer, or your own lab fabric) in passive
mode, so it only ever receives:

```toml
# gobgpd.conf
[global.config]
  as = 65000
  router-id = "192.0.2.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.13"
    peer-as = 65001
  [neighbors.transport.config]
    passive-mode = true
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
```

```bash
gobgpd -f gobgpd.conf &
gobgp global rib -a ipv4            # the whole table you received
gobgp global rib 203.0.113.0/24     # one prefix, every path you saw
```

No neighbour to spare? Take the view straight off a router you already run. FRR (or any Cisco/Juniper box)
will stream its tables over BMP to a collector, with no CLI scraping. Add a BMP listener to the same gobgpd:

```toml
[[bmp-servers]]
  [bmp-servers.config]
    address = "0.0.0.0"
    port = 11019
```

```
! on the FRR router, under: router bgp 65001
 bmp targets EYES
  bmp connect 192.0.2.1 port 11019 min-retry 1000 max-retry 5000
  bmp monitor ipv4 unicast pre-policy
```

## Knowing what the table thinks of you

Propagation is half the question; validity the other half. Routinator turns the published ROAs into a
verdict for a prefix and origin:

```bash
routinator init --accept-arin-rpa
routinator vrps                                   # every validated payload
routinator validate --asn 65020 --prefix 203.0.113.0/25
# -> Valid | Invalid | NotFound
```

Run it before announcing to see whether an origin reads as invalid anywhere that enforces, and afterwards to
see whether a more-specific slipped through a gap. It is the same validator a careful network runs to protect
itself, which is the running joke of this section.

## The record

For "what did it look like an hour ago", the archives. RouteViews and RIS publish MRT dumps, both RIB
snapshots and update streams, going back years:

```bash
wget https://routeviews.org/route-views2/bgpdata/2026.06/UPDATES/updates.20260613.0800.bz2
bgpdump -m updates.20260613.0800.bz2 | grep '203\.0\.113'
```

`-m` prints one machine-readable line per record: timestamp, peer, AS path, prefix. `mrtparse` and
`pybgpstream` read the same files if you would rather stay in Python.

## Two things no command fixes

A single collector sees the table its neighbours offered, not the one everyone else sees. More sight comes
from more feeds, never from inventing routes the collector did not receive: the moment the view is
fabricated it stops being an eye and becomes a mirror. And the footprint moves rather than vanishes. A
peering is a relationship someone can name; a RIS Live subscription is a connection a public service logs.
Listening is quieter than announcing, but quiet is relative, and the view cuts both ways.
