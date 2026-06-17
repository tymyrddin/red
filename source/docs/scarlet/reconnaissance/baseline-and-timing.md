# Normal, and when to break it

An anomaly hides best inside noise. The last piece of reconnaissance is learning a prefix's normal, so that a
later change can be judged against it, and choosing a moment when normal is already moving.

## RIB or updates

The collectors offer two things, and they answer different questions. A RIB snapshot is the whole table at an
instant, for "what did this look like at 08:00". An update dump is the stream of changes, for "what moved, and
when". Baselining pulls a RIB for the steady state and the updates for the movement around it. An MRT dump
reads with `bgpdump`:

```
bgpdump -m bview.20260613.0800.gz | grep '|203.0.113.0/24|'
```

```
TABLE_DUMP2|1781337600|B|206.126.236.21|6939|203.0.113.0/24|6939 3356 64500|IGP|...
```

Across many peers, that one prefix gives its normal: the usual origin (`64500`), the typical path length, and
the handful of upstreams that recur. The update dumps for the same window show how often any of it changes.

## What normal looks like

![the budget as deviation against a baseline](/_static/images/06a-the-budget.png)

A stable prefix has one origin, a narrow spread of path lengths, a small recurring set of upstreams, and long
quiet stretches between updates. Each of those is a baseline figure, not a vibe. A prefix that already flaps,
or that legitimately appears behind several origins, has a wider normal and so a larger budget for a change to
sit inside unnoticed. The narrower the normal, the smaller the room.

SIDN Labs' [Noisy Routers: Investigating the Make-up route collector data](https://www.sidnlabs.nl/en/news-and-blogs/noisy-routers-investigating-the-make-up-route-collector-data)
analysed more than 80 billion updates and found a small set of peers and prefixes generating most of the
churn, a reminder that a baseline worth keeping ranks paths as stable, noisy, or anomalously noisy rather than
treating every update alike.

## The budget

A baseline turns "is this suspicious" into arithmetic. An announcement that keeps the prefix's usual path
length, a reachable next-hop, and avoids flapping reads as routine; one that adds two AS hops, or a new
origin, or oscillates, spends the budget fast. The figure worth writing down is the deviation a watcher would
tolerate before a human looks, because that is the size of the move available.

## When normal is already moving

Two kinds of moment matter, for opposite reasons.

![timing fork between cover and visibility](/_static/images/06b-timing-fork.png)

Cover: maintenance windows, unrelated outages, and global churn. Operator maintenance is often pre-announced
on NANOG and regional lists, and large events leave a clear trace in the update dumps. During churn the
baseline is already noisy and attention is elsewhere, so a change blends in.

Visibility: an election, a press conference, peak business hours. These are the inverse choice, taken when the
aim is to be felt rather than to hide. The calendar, not the routing table, picks these.

A private listener, rather than repeated public queries, keeps the baselining itself off someone else's logs;
building one is covered under [eyes/](../eyes/index.rst).
