# Delivery mechanisms

A payload that sits on the attack server reaches nothing. Delivery is the bridge from the operator's
infrastructure to the target's environment, and the mechanism chosen shapes both the probability of execution
and the attribution trail it leaves. Each mechanism carries different artefacts, different timelines, and
different opsec implications for the infrastructure behind it.

## Phishing

Spear-phishing is the most common initial access vector in targeted operations. A well-crafted pretext, aligned
to the target's role and the current context (an HR communication, a vendor invoice, a colleague's calendar
invite), substantially increases the probability of execution over generic lures.

The payload arrives either as an attachment or as a link. Attachment delivery embeds the payload directly;
link delivery points the target at a URL behind the [frontend](../frontend/nginx.md), which serves the payload
on the beacon path and a plausible cover page everywhere else. Link delivery keeps the payload off email
scanning infrastructure; attachment delivery avoids the extra network hop and works against targets behind
egress filtering that blocks unfamiliar domains.

The sender domain is part of the [masquerading](../frontend/masquerading.md) decision: it wants to look like
something the target expects to hear from, aged enough to pass reputation filters, and categorised correctly
before the campaign launches.

## Drive-by

A watering hole places the payload on a site the target visits, rather than going directly to the target.
Compromising a third-party site the target's team uses (a forum, a vendor portal, a community resource) and
injecting a delivery mechanism reaches the target without the target needing to act on an inbound message.

The payload delivery happens through the browser: a JavaScript stager that fetches and executes the implant,
or a redirect to a URL that triggers a download. Both need the delivery URL to be behind the [redirector
chain](../redirectors/nginx-redirector.md) to keep the C2 address off the compromised site.

Drive-by scope is a function of how many people visit the watering hole. Indiscriminate deployment at a
high-traffic site risks reaching far beyond the intended target, which conflicts with most engagement scopes.
Pre-condition the payload delivery on a fingerprint of the intended target where possible.

## Physical

USB drops and pre-loaded devices place the payload without any network activity at delivery time. A device left
in a plausible location (a meeting room, a reception desk) relies on a target plugging it in. A badUSB device
enumerates as a keyboard and types the payload delivery commands itself.

Physical delivery sidesteps email scanning and URL filtering entirely. It also requires physical access to the
target's environment, which is a different kind of preparation from the network-side infrastructure this section
covers.

## Supply chain

Dependency confusion and package typosquatting place a malicious package where a target's build pipeline will
fetch it. A package name matching an internal module, published to a public registry, may be pulled
automatically during a build if the registry search order favours public over internal. The payload executes in
the context of the build agent, often with substantial network access.

Scoping matters especially here. Supply chain access tends to be wide; a single package reaches every
developer and build system pulling it. Engagement contracts vary in whether this technique is in scope, and the
blast radius is worth establishing explicitly before use.
