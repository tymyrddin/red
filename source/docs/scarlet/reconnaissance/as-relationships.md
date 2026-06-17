# Reading the relationships

BGP does not publish who is whose customer, but the routes carry enough to infer it, and several projects have
already done the inference. Knowing which relationship an announcement rides often decides whether it wins.

## The path is the record

Every route carries an AS_PATH: the sequence of ASes it crossed, newest first, origin last. A collector that
sees

```
203.0.113.0/24   path: 6939 3356 64500
```

is reading "to reach `203.0.113.0/24`, go to AS6939, which heard it from AS3356, which heard it from the
origin AS64500". Path length is the rough tiebreak when specificity is equal, so a shorter path tends to win
traffic. The path is also where prepending shows up: an origin that announces `64500 64500 64500` is padding
its own path to look further away and repel traffic, a legitimate steering trick that doubles as cover.

## Customer, peer, provider

![ customer/peer/provider shape and the valley-free rule.](/_static/images/02-relationships.png)

Money flows one way and routes flow the other. A customer pays a provider for reach to everywhere. Two peers
swap their own and their customers' routes for free, and carry nothing else for each other. This gives the
valley-free rule: a path goes up to providers, across at most one peer link, then down to customers, and
never climbs back up. A path that goes up, across a peer, then up again is a leak, and it stands out precisely
because it violates that shape.

CAIDA publishes inferred relationships (the serial-1 dataset) as pipe-delimited triples:

```
3356|64500|-1     # AS3356 is a provider of AS64500
174|3356|0        # AS174 and AS3356 are peers
```

`-1` reads as "first is provider of second"; `0` reads as "peers". AS-rank presents the same data with a
browsable graph, which is usually enough to reason about who would accept what from whom.

The research direction is to learn these relationships rather than tabulate them:
[Thales: An orientation-aware AS embedding for anomaly detection in dynamic BGP network](https://www.sciencedirect.com/science/article/abs/pii/S1389128625009120)
builds representations of AS roles and path structure that update as the topology shifts.

## Declared intent

An `aut-num` object states an AS's own import and export policy, and reveals homing:

```
aut-num:   AS64500
import:    from AS3356 accept ANY
export:    to AS3356 announce AS64500
import:    from AS174 accept ANY
export:    to AS174 announce AS64500
```

Two upstreams (AS3356 and AS174) means multi-homed: there is more than one path in and out, which is where
path games and leaks have somewhere to go. A single `import`/`export` pair means single-homed, with one
upstream and few options. The same can be confirmed from observation: count the distinct second-to-last hops
across many collected paths for the prefix, and that is the set of upstreams actually in use.

![the selection ladder showing why local preference outranks path length.](/_static/images/03-selection-ladder.png)

## Why it decides the outcome

Route selection weighs local preference first, and operators commonly set customer-learned routes above
peer-learned above provider-learned, because a customer route is the one they are paid to carry. Local
preference outranks path length entirely. So a route injected through a customer relationship can beat a
shorter, legitimate route learned from a peer, on policy alone. The relationship an announcement rides is not
a detail; it can be the whole reason it wins.
