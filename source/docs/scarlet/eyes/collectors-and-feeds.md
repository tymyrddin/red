# Collectors and feeds

A looking glass answers when you ask. A collector never stops listening. Two public projects run fleets of route 
collectors that peer widely and write down everything they hear, both as a live stream and as an archive years deep. 
This is the record you check to prove a route propagated, and the one you read to learn a prefix's normal.

## RIPE RIS

RIPE's Routing Information Service runs around twenty Route Collectors (the RRCs) at exchanges worldwide, and offers the
data two ways:

* RIS Live: A streaming websocket of updates as the collectors see them, in JSON. Real-time, no account, filterable
  by prefix, path, or peer.

```text
wss://ris-live.ripe.net/v1/ws/
```

* Raw MRT: RIB snapshots every eight hours and update dumps every five minutes, archived per collector at
  `data.ris.ripe.net`, going back years.

## RouteViews

The University of Oregon's RouteViews is the other long-running collector network, independent of RIS and so a useful 
second opinion. It publishes MRT only: RIB snapshots every two hours, updates every fifteen minutes.

```bash
wget https://archive.routeviews.org/route-views2/bgpdata/2026.06/UPDATES/updates.20260613.0800.bz2
bgpdump -m updates.20260613.0800.bz2 | grep '1\.1\.1\.'
```

## One library over both

[CAIDA BGPStream](https://bgpstream.caida.org) puts RIS and RouteViews, live and archived, behind one interface: a 
`bgpreader` command line and a `pybgpstream` binding. When you want both sources without minding their individual file
paths or formats, it is the shortest path. 

Exact flags come from `bgpreader -h`:

```bash
bgpreader -p ris-live -k 1.1.1.0/24
``` 

## RIB or updates

The two formats answer different questions. An RIB snapshot is the whole table at a moment, for "what did it look like 
at 08:00". An update dump is the changes, for "what moved, and when". Most analysis pulls a RIB for the baseline and 
the updates for the surrounding movement. 
