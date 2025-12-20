# Control plane versus data plane

*Or: the difference between forging letters and rewriting the Guild Registry*

Ankh-Morpork does not function because it is well governed. It functions because everyone agrees, more or less, on 
where authority lives.

For centuries, that authority has been the *Guild Registry*.

- Want to know who is allowed to operate as a Thief? Registry.
- Want to know whether someone claiming to be a Seamstress is entitled to the title? Registry.
- Want to know whose word counts when two guilds disagree? Registry again.

The entire city’s trust infrastructure rests on one quiet assumption: *the Registry is correct*.

This distinction matters when we talk about BGP attacks, because most things labelled “control-plane attacks” are not. 
They are, at best, forged letters carried by an overly trusting postal service.

Let us be precise.

## The postal system (data plane abuse)

Most well-known BGP incidents operate like this:

Someone sends convincing letters. The Post Office delivers them faithfully. Chaos ensues.

Nothing about the Registry changes. Authority still exists. It is simply *misapplied*.

These incidents manipulate *routing announcements*, which are messages saying “send traffic this way”. They exploit 
trust, habit, and the fact that the city prefers the loudest or most specific instruction.

### Fat-finger hijacks

A clerk accidentally posts a notice claiming responsibility for streets they never intended to manage. The city 
believes them, because why would anyone lie about that?

([Fat finger hijack](fat_finger_hijack): This is not an attack on authority. It is a mistake that the system is 
structurally incapable of containing.

The Registry still says who is legitimate. Nobody bothered to check it.

### Sub-prefix intercepts

A smaller, more specific sign is nailed up next to the official one. BGP, like Ankh-Morpork’s citizens, follows the most precise instruction available.

[Subprefix Interception with Polite Forwarding](subprefix_intercept.md): Traffic obediently detours through an unexpected alley.

Again: the Registry is untouched. The rules have not changed. The city simply followed the wrong signpost.

## The Guild Registry (true control-plane attacks)

A *control-plane attack*, properly defined, does not lie *within* the rules.

It *rewrites the rules themselves*.

Imagine someone breaks into the Guild Registry at night and quietly edits the ledger:

* The legitimate Guildmaster’s name is removed
* A different name is inserted
* All future checks now reject the real authority and accept the imposter

From that moment on, everyone is “following the rules”. The rules are simply wrong.

That is a control-plane attack.

In BGP terms, this means manipulating the *authoritative systems that define legitimacy*, not just the messages that claim it.

### ROA poisoning

RPKI ROAs are meant to answer one question: *who is allowed to announce this prefix?* They are the modern Guild Registry.

If an attacker can:

* Create fraudulent ROAs
* Modify or revoke legitimate ones
* Or compromise the systems that distribute or validate them

then routers do not merely receive false information. They receive *authoritatively wrong truth*.

[Control-Plane Poisoning with Operational Cover](roa_poisoning.md): Valid routes are rejected. Invalid routes are 
accepted. Not because of misdelivery, but because legitimacy itself has been redefined.

This is not a forged letter. This is editing the ledger.

## Why this distinction matters

Because defences depend on what you think is under attack.

If you believe the problem is forged letters, you focus on:

* Detection
* Monitoring
* Faster response
* Better filtering

If you realise the problem is Registry tampering, you worry about:

* Trust anchors
* Governance
* Automation pipelines
* Who is allowed to define “valid”, and who audits them

The first problem causes outages. The second causes quiet, systemic failure.

## A final word from the city

Ankh-Morpork has survived floods, fires, dragons, and civic planning.

What it fears most is not the thief in the street, but the clerk in the records office with a steady hand and no witnesses.

Most BGP incidents are noise in the post. 

Control-plane attacks are edits to reality.

Confuse the two, and you will defend the wrong thing very well indeed.
