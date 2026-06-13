# Looking glasses

The quickest sight is someone else's. A looking glass is a public window onto one
network's routing table: ask it about a prefix, and it shows what that network
sees, from where it sits. You touch nothing of the target and stand up nothing of
your own. The catch is the catch of any borrowed thing. The view is theirs, partial
to their vantage, and your question lands in their logs.

## The web windows

Most large networks and exchanges run a looking glass you can click through.
[Hurricane Electric's](https://lg.he.net) is the usual first stop for a global
view; [Packet Clearing House](https://www.pch.net/tools/looking_glass) spans a wide
set of exchanges; and most transit providers run their own, which is the one to
reach for when you care how a particular network sees a prefix.

## The ones that script

Web glasses suit a glance. For anything repeatable, RIPEstat answers over HTTP with
no account and returns, per collector, every peer's path and the origin AS, which
is enough to spot a second origin on the same prefix:

```bash
curl -s 'https://stat.ripe.net/data/looking-glass/data.json?resource=1.1.1.0/24' | jq
```

[bgp.tools](https://bgp.tools/) offers the same view over a whois interface and an API, terse and fast;
its query forms are on its own site. Many ISP glasses are web or telnet only, so
RIPEstat is the one that scripts cleanly.

## One window is one opinion

A looking glass shows the table its operator's peers offered, which is not the
table everyone sees. A prefix can read clean from one glass and contested from
another. Reading two or three from different regions is the cheapest way to tell a
local quirk from something global. 

And every query leaves a footprint: borrowed sight is sight you asked for by name, leaving your own IP address in the looking glass's logs.
