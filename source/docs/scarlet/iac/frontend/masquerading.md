# IP masquerading

The frontend hides the C2 behind a normal-looking domain. The blue team's first impression lands on a brochure
site, not a beacon endpoint.

## Domain selection

Buy two types of domain per operation:

* One for workstation reverse shells: a profile that fits the target's expected outbound web traffic. Marketing,
news, SaaS, software updates.
* One for server callbacks: something that fits server-to-server traffic. Telemetry endpoints, package mirrors,
monitoring APIs.

Mixing the two on a single domain is loud. A workstation talking to an "update server" once a week is fine; a
workstation talking to a "monitoring API" is suspicious.

## Aging and reputation

* Avoid freshly registered domains. Many DNS-layer filters block any domain younger than seven to thirty days.
* Buy domains that are at least a few months old. Drop-catch services and aged-domain marketplaces sell these,
but vet for prior abuse history.
* Check reputation against URLhaus, VirusTotal, Cisco Talos, and the major DNS filters before going live.
* Avoid TLDs with a poor reputation (.tk, .top, .xyz often get scored down even when clean).

## Categorisation

Web filters route allow and deny decisions through category vendors (Cisco Talos, Palo Alto, Broadcom Web Security, Zscaler).
A new domain sits in "uncategorised" by default, which many enterprises block outright. Submit the cover site to
each vendor's recategorisation portal once it is serving real-looking content.

## One domain per operation

Burn the domain at the end of the engagement. Reusing names across operations links them under shared reputation
lookups. Park the old DNS at a sinkhole or remove it entirely.

## Cover content

The frontend serves plausible content on `/` and on any path the beacon does not claim. A static brochure
site is enough. Keep it boring; do not link to anything on the open web from it.