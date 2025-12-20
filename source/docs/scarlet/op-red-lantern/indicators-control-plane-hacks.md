# Indicators that control‑plane attacks exist

*And why you never see them in public*

In Ankh‑Morpork, everyone knows about street crime. Pickpockets, confidence tricksters, the occasional dragon. These are visible, noisy, and comforting in their familiarity.

What nobody discusses over lunch is the Registry.

Not because nothing happens there, but because **anything that does happen there is immediately classified, quietly fixed, and never spoken of again**.

The same is true for control‑plane attacks on Internet routing.

## First, the uncomfortable premise

If you are asking: *“Do control‑plane attacks on BGP actually exist?”*

Then the honest answer is:

**Yes — at least at nation‑state level — and the absence of public case studies is itself one of the strongest indicators.**

In Ankh‑Morpork terms: if the Guild Registry were ever tampered with successfully, you would not hear about it from the Watch. You would hear about it by noticing that certain people stopped being recognised as legitimate, and nobody could explain why.

## What would count as an indicator?

We are not talking about:

* Fat‑finger leaks
* Sub‑prefix hijacks
* Loud routing accidents that break half the city

Those are street crime.

Indicators of *control‑plane attacks* are quieter, stranger, and usually discovered *after the fact* by people who are not allowed to write blog posts about them.

Here are the categories that matter.

## 1. Unexplained legitimacy failures

The clearest indicator is this: *Routes that are demonstrably correct are suddenly, persistently, and selectively treated as invalid.*

Not everywhere. Not loudly. Just enough to matter.

Examples (as patterns, not disclosures):

* ROAs that appear unchanged, yet validation outcomes differ across regions
* Long‑standing prefixes becoming “invalid” without a corresponding registry action
* Legitimate announcements rejected only by certain major transit providers

In Ankh‑Morpork: the Guildmaster turns up at the door and is told, politely, that the Registry says they do not exist.

## 2. Asymmetric validation behaviour across blocs

Another indicator is **geopolitical asymmetry**.

Some parts of the city accept a route. Others do not.
The split aligns suspiciously well with national or alliance boundaries.

This suggests:

* Divergent trust anchors
* Selective policy enforcement
* Or private validation logic layered on top of public standards

Nothing is “broken”. Everyone insists they are following the rules. They are just not following the *same* rules.

## 3. Sudden changes in routing policy consumption

Modern routing is not configured by hand. It is built by machines, from data sources few people audit.

Indicators include:

* IRR or RPKI data changing in ways that propagate unusually fast
* Policy generation pipelines accepting objects they previously rejected
* Communities or attributes gaining new semantic meaning without documentation

In Ankh‑Morpork terms:
the Registry’s handwriting changes overnight, but only for certain pages.

## 4. Attacks that leave no packet‑level artefacts

This is critical.

A true control‑plane attack may:

* Never intercept traffic
* Never drop packets
* Never appear in NetFlow or PCAP

Its purpose is often **denial of legitimacy**, not interception.

If you are only watching traffic, you will miss it entirely.

The victim experiences:

* Reachability problems
* Inexplicable filtering
* “Works from here, not from there” behaviour

And no smoking gun.

## 5. Behaviour consistent with intelligence objectives

Nation‑state actors do not need to hijack YouTube.

They need to:

* Isolate specific networks
* Degrade trust in certain providers
* Shape routing choices during crises
* Prepare the ground for future operations

Control‑plane manipulation is ideal for this:

* Low noise
* Plausible deniability
* Reversible
* Attributable to “misconfiguration”

Exactly the sort of thing you would never see in a public incident report.

## Why none of this is public

This is the part people dislike.

### 1. Disclosure would expose trust anchors

Publicly admitting a successful control‑plane attack would mean admitting that:

* A registry
* A certificate authority
* Or a validation mechanism

cannot be fully trusted.

That is not a bug report. That is a systemic confidence crisis.

### 2. Detection itself is often classified

Many of the strongest indicators come from:

* National monitoring infrastructure
* Privileged routing vantage points
* Intelligence‑grade correlation

If you publish how you detected it, you teach others how to evade it.

So you do not publish it.

### 3. Attribution is politically radioactive

A fat‑finger can be blamed on a junior engineer.

A control‑plane attack implies:

* Capability
* Intent
* Long‑term access

Those words tend to summon diplomats.

It is far safer to quietly fix the Registry and say nothing.

### 4. The ecosystem is not ready for the conversation

Routing still runs on:

* Mutual trust
* Gentlemen’s agreements
* And the assumption that nobody would dare touch the Registry

Publicly acknowledging that some actors already have would require:

* Governance reform
* Hard enforcement
* Real accountability

None of which the city enjoys.

## The Ankh‑Morpork conclusion

Street crime is discussed endlessly because it is survivable.

Registry tampering is not discussed because:

* It undermines the idea that the city knows who is legitimate
* It reveals that authority itself can be forged
* And it raises questions nobody wants to answer in public

So yes, the indicators exist. They are seen. They are tracked. And they are not published.

In Ankh‑Morpork, if the Guild Registry ever truly burns, you will not read about the fire.

You will just wake up one morning and discover that your name no longer counts.
