# Extraction

Extraction is the attack through the front door. Every query the attacker sends returns an answer,
and every answer carries a bit of information about the function that produced it. Collect enough of
them and the answers add up to a working copy of the model, or at least a copy good enough to plan
against. Nothing is broken into. The interface did what it was built to do, one query at a time.

What makes this specific to a learned model is that the model is the value and the model is also the
output. A written rule can be published without much loss; the rule was the cheap part and the data
behind it stays put. A trained model embeds the data, the labelling effort, and the tuning, and it
leaks a sample of all three with every prediction. The cost of building it was high and the cost of
querying it is low, and extraction lives in that gap.

## The query interface

- Moderation and abuse classifiers exposed through a submission or preview endpoint.
- Fraud and risk scores returned, even indirectly, to the party being scored.
- Pricing, ranking, or recommendation models whose outputs are observable.
- Any model behind an API where the caller sees the label, the score, or just the outcome.

The query interface is the whole attack surface. The richer the response, a full probability vector
rather than a bare label, the faster the model gives itself up.

## Turning outputs into a replica

*Functional extraction of a classifier through its own answers*: An attacker submits a broad, varied
stream of inputs, records each label, and trains a substitute model on the input-label pairs. The
substitute need not match the original's internals; it needs to agree on the outputs. Once it agrees
closely enough, the attacker owns a local copy they can study without limit and without being watched.

*Mapping the boundary to build evasion offline*: Extraction and evasion compound. An attacker who
reconstructs the decision boundary can craft evasive inputs against the local copy at leisure, with
no query budget and no detection risk, then bring the finished attack to the real model in a single
clean pass. The probing that evasion would otherwise do live is done once, offline, against the stolen
function.

*Recovering thresholds from confidence scores*: A model that returns a probability rather than a flat
decision hands the attacker a gradient. By walking an input across the threshold and watching the
score move, they read off where the boundary sits and how steep it is, turning a few hundred queries
into a precise map of the model's mind around the inputs they care about.

*Lifting the logic of a pricing or risk model*: Where the output is a number the attacker can observe,
a price, a limit, a risk band, repeated queries that vary one factor at a time reveal how each factor
moves the result. The model's commercial logic, the thing the business treated as proprietary, comes
out in the responses without a line of it ever being disclosed.

*Sanitisation that cannot help here*: Input sanitisation rejects malformed or hostile input. Every
extraction query is well-formed, in range, and individually unremarkable; the attack is in the
aggregate, in the pattern across thousands of legitimate calls. The layer that inspects one input at
a time has nothing to object to, because no single query is the attack.

The mechanics are straightforward. An attacker submits a large, systematically varied stream of queries and records each
input alongside its output. That dataset of (input, output) pairs is then used to train a substitute model. The
substitute does not need to replicate the original’s architecture; it needs to agree on its outputs across enough of the
input space. Once it does, the attacker owns a private simulation environment: in the fraud case, they test candidate
transactions against the clone until they identify patterns the model does not flag, then submit those to the real
system.

## Commercial and military applications

### Competitor model extraction via API

A company that has spent heavily training a large language model and serves it through a public API faces a structural
tension: the accuracy that makes the API valuable is the same accuracy that makes extraction feasible. A well-funded
competitor can spend a fraction of the original training cost in query fees, submit a systematically varied stream of
prompts, collect the outputs, and train a substitute on the resulting dataset. The substitute is not the original model;
it is a model that agrees with the original on most inputs. That agreement is often sufficient. The value extracted is
not code or weights but learned behaviour, and learned behaviour transfers through the output channel the product was
built to provide. Several legal disputes between AI companies have centred on exactly this boundary between legitimate
API use and systematic knowledge distillation.

### Acoustic classification via crafted queries

An AI classifying submarine acoustic signatures, trained on decades of classified recordings, is precisely the target
extraction is designed for: high training cost, accessible query interface, and outputs that carry information about
what the training data contained. A surveillance platform generating and observing responses to carefully varied
acoustic probes can accumulate a dataset from which a substitute classifier is trained. Once the substitute is accurate
enough, the adversary can design propulsion signatures that both the clone and, by transfer, the original system are
likely to misclassify. The attack required no access to the model, the training data, or the hardware: only patience and
a way to observe the outputs.

### Targeting system extraction through a captured terminal

A proprietary targeting system accessible only through a secured field API remains vulnerable to extraction as long as
an adversary can submit inputs and observe outputs. A captured terminal provides exactly that. Rather than attempting to
break the encryption, an adversary feeds battlefield images through the terminal, records the classifications, and
trains a substitute at a remove. The clone allows testing of camouflage, decoy placement, and formation geometry against
a model approximating the opponent’s targeting logic, before committing to any of those strategies in the field. Total
tactical transparency, at the cost of a few thousand queries.

### Graph neural network extraction in 100 queries

Research published in 2024 demonstrated
that [graph neural networks can be extracted](https://arxiv.org/abs/2511.07170) with as few as 100 queries
to the victim model, achieving 91% accuracy compared to the 5,000 queries required by previous methods. The attacker
recovers the model backbone without querying the victim directly in some configurations. The significance is the query
economy: as extraction becomes cheaper, the class of models worth extracting expands, and rate limits calibrated against
older methods become inadequate.

### Extracting commercial AI patterns for malware development

The [GREYVIBE group](https://healsecurity.com/greyvibe-hackers-leverage-chatgpt-and-google-gemini-to-fuel-cyberattacks/)
uses commercial AI APIs to accelerate development of malware and post-compromise tooling. By extracting behavioural
patterns and code generation capabilities from these APIs, they produce novel malware components with reduced reliance
on reused code. Reused code is the primary signal attribution analysis looks for; extraction-assisted generation
degrades it. The defender’s AI sees outputs that resemble legitimate API use; the result is malware that evades both
detection and attribution.

## Detection limits

Detection depends on distinguishing extraction queries from legitimate use, and the two are hard to separate at the
level of individual requests.

An adversary with resources can distribute extraction probes across patterns that resemble genuine use. Seeded into a
stream of mundane requests, homework help, code assistance, translation, the probes are individually unremarkable. A
filter that inspects one call at a time has nothing to flag. Rate limiting slows the extraction without stopping it;
adjusting query pace is a trivial countermeasure.

The deeper tension is that accuracy and extractability move together. A model returning precise probabilities rather
than coarse decisions is more useful and more legible to an extraction attack. Reducing output precision reduces the
information yield per query but also reduces the product’s value. Adding noise to outputs degrades accuracy. Making the
model large enough that cloning it requires prohibitive compute raises the bar, but as compute costs fall, that
threshold shifts.

Legal remedies exist but are slow. The attacker can frame systematic querying as legitimate API use, with fair use or
research purposes as a possible defence; whether that framing holds is legally unsettled, and the uncertainty is part
of what slows proceedings. By the time proceedings conclude, a cloned model may already be in wider circulation.
The more useful question is often not whether extraction can be prevented, but what a working clone would enable, so
that the downstream consequences are anticipated rather than discovered.

## Limiting the information yield

Treating high-volume, high-coverage querying as a signal in itself, separate from whether any one
query looks abusive. An account systematically sweeping the input space is doing something a genuine
user rarely does, and the pattern is visible at the account level even when each call is clean.

Returning less than the model knows. A bare label leaks less than a calibrated probability, and a
coarse band leaks less than a precise score. What the response withholds is what the attacker cannot
reconstruct.

Rate limiting and per-caller query budgets, sized to legitimate use. Extraction needs volume;
constraining volume raises the cost of a usable copy and buys time to notice the sweep.

Accepting that a sufficiently determined caller with enough budget can approximate the model, and
deciding in advance what that copy would let them do, so the consequence of extraction is planned for
rather than discovered.

## Counter moves

The defender's view, including what a working clone would let an attacker do offline, is in the
purple notes on [AI in security operations](https://purple.tymyrddin.dev/docs/ai-security/).

## Related

* [Threat analysis of AI in security operations](https://purple.tymyrddin.dev/docs/ai-security/)
* [Attack path mapping](https://purple.tymyrddin.dev/docs/threat-modelling/attack-path-mapping/)
* [The calibration view](https://purple.tymyrddin.dev/docs/adversarial-ai/)
