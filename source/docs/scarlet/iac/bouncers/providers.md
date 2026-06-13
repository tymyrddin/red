# VPS providers

Every VPS account creates a record somewhere. The question is whose record, what it contains, and how quickly it
surfaces when someone asks. Payment method is the primary axis: a credit card ties the account to a name and
address that survives the operation. Cryptocurrency narrows the trail to a wallet; whether that wallet traces back
to anything depends on how it was funded. The hosting choice is the second axis: large providers with mature
abuse teams respond to takedown requests within hours; smaller European operators may take longer and vary in
how far they cooperate with requests from outside their jurisdiction.

## Identity-bound providers

The major cloud platforms (AWS, Google Cloud, Microsoft Azure, OVHcloud, Hetzner) all require verified payment
and operate abuse or law-enforcement response teams. They are poor choices for any host the target ever sees.

Two narrow cases where they remain useful:

* The engagement contract explicitly permits cloud-of-record infrastructure for billing and audit reasons.
* The host is on the management side only and the target never touches it. The billing identity is still a
permanent link, so this works only when that link is acceptable under the scope.

For anything target-facing, use one of the alternatives below.

## European alternatives

These providers accept cryptocurrency or have a lighter identity footprint and are based in or operate primarily
in European jurisdictions.

[1984 Hosting](https://1984.hosting/) (Iceland) accepts Bitcoin and Monero, has a public commitment to privacy,
and sits in an EEA jurisdiction with its own data protection regime separate from EU requirements. Minimal signup
friction and a reputation in the privacy and security communities that has held since 2006. Entry VPS is around
€8.72 per month for 1 CPU, 1 GB RAM, and 25 GB NVMe.

[FlokiNET](https://flokinet.is/) (Iceland, Romania, Netherlands, Finland) accepts Bitcoin, Monero, and other
cryptocurrency, and explicitly positions itself as a privacy and free-speech host. Instances in Romanian and Dutch
datacentres are reachable with lower latency from most European targets than Icelandic alternatives. Pricing
varies by location; expect €5 to €10 per month for a basic instance.

[Njalla](https://njal.la/) (offshore, Swedish founders) was built from the start around the separation of legal
ownership from operational use: Njalla holds the registration, the operator holds a usage agreement. VPS and
domain registration available together, which simplifies the anonymous-payment chain. Cryptocurrency accepted.
Around €15 per month for a VPS with reasonable specs.

[Cinfu](https://www.cinfu.com/) (Bulgaria, France, Germany) accepts cryptocurrency and offers instances across
multiple European datacentres, which can be useful when geographic spread of bounce servers is wanted within a
single provider relationship. Around €4 to €5 per month for a 2 GB instance, varying by datacenter availability.

[NiceVPS](https://nicevps.net/) accepts cryptocurrency for VPS and domains together, keeping the registration
and hosting under a single anonymous-payment account. Pricing starts around €9.99 per month; the combined domain
offering is what distinguishes it from the cheaper options above.

## Choosing and rotating

For redirectors and bounce servers that the target may ever touch, prefer the alternatives above, paid with
cryptocurrency sourced as described in [anonymous payments](payments.md). Burn the account per operation where
possible; a provider account reused across engagements accumulates correlating indicators even if each individual
host is torn down.

For management-side hosts, the [Terraform-integrated providers](../automation/providers.md) (Hetzner, Vultr,
DigitalOcean) are more practical to automate, at the cost of the identity tie.

No provider is permanent. Check that the service still accepts cryptocurrency and is still operating before an
engagement; the smaller operators on this list change terms with less notice than the majors.
