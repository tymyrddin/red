# Surveying the defences

Inter-domain security in 2026 is unevenly deployed, and the unevenness is public. This page reads the coverage
on a prefix before anything is announced: where origin validation would catch a forged route, and where it
would not.

## What a ROA is

The main defence is RPKI, the Resource Public Key Infrastructure. A network publishes a Route Origin
Authorisation (ROA): a signed statement "this AS may originate this prefix, up to this length". A ROA has
three fields, and tools render them plainly:

```
ASN       Prefix            Max Length
AS64500   203.0.113.0/24    24
```

Route Origin Validation (ROV) checks a received route against the ROAs and returns one of three states:

```
valid       origin and length match a ROA
invalid     a ROA exists, but the origin or length disagrees
not-found   no ROA covers this prefix at all
```

The gap to read is between `invalid` and `not-found`. Many networks drop `invalid` but accept `not-found`, so
an unsigned prefix can be announced from the wrong origin without ever turning `invalid`. And a ROA for
`203.0.113.0/24` with max length `24` makes a `/25` `invalid`, whereas max length `25` would have authorised
every `/25` inside it. The max-length field is where loose ROAs leave room.

![the ROV state gap](/_static/images/05a-rov-states.png)


## Reading it without touching anything

A live validity and origin view, per prefix:

```
https://bgp.tools/prefix/203.0.113.0/24      # shows RPKI: Valid / Invalid / Unknown
```

The published ROAs themselves come from any validator's output. Routinator and rpki-client both emit the full
validated set (VRPs) as CSV, which greps cleanly:

```
routinator vrps --format csv | grep 203.0.113
```

```
AS64500,203.0.113.0/24,24
```

No ROA line for a prefix means `not-found` everywhere, which is the softest case.

## Enforcement is separate from publication

![the survey logic of where the openings sit](/_static/images/05b-coverage-survey.png)

Publishing a ROA and enforcing ROV are different acts. Which upstreams actually drop invalids, and which only
log them, varies by operator and region, and a single upstream that enforces validation can defeat a forged
origin outright. The practical survey is a search for a path with no enforcement on it, read from the
relationships and observed upstreams rather than asserted from the ROA alone.

For where this tends to break, [SoK: An Introspective Analysis of RPKI Security](https://papers.cool/arxiv/2408.12359)
catalogues how RPKI fails in practice, which doubles as a list of the gaps a survey is looking for.

## IRR hygiene

Older than RPKI, the Internet Routing Registries hold route objects that automated prefix filters still trust.
Stale or over-broad objects let a filter accept what it would otherwise reject. IRRexplorer shows where
registry data and RPKI disagree, and that disagreement is exactly where ambiguity lives:

```
https://irrexplorer.nlnog.net/prefix/203.0.113.0/24
```

To see what an upstream's filter would actually permit for a customer, generate it the way operators do, with
`bgpq4`:

```
bgpq4 -4 -l TARGET AS64500
```

```
ip prefix-list TARGET permit 203.0.113.0/24
```

A filter built from a loose `as-set` lists more than the customer actually announces, and the surplus is the
opening.
