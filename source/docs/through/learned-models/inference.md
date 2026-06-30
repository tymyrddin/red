# Inference

Inference is the attack that runs the model backwards. Extraction steals what the model does;
inference steals what the model knows, recovering facts about the training data from the model's
behaviour on the outside. The data was meant to stay inside the weights as statistics. Inference
attacks treat the weights as a lossy archive and try to read the archive back out.

What makes this specific to a learned model is that training is a form of remembering. A model fits
its data, and in fitting it retains traces of the individual records, more so where data was scarce,
a class was rare, or training ran long. Those traces are not addressable like a database row, but
they are not gone either, and the model's outputs are shaped by them in ways an attacker can probe.
When the training data was personal, the model becomes a surface through which personal data can
leak without any record ever being copied.

## Models trained on sensitive data

- Models trained on customer, transaction, or health records.
- Fraud and risk models fitted on labelled cases tied to real people.
- Language models fine-tuned on internal documents, tickets, or chat logs.
- Any model whose training set would be sensitive if disclosed directly.

The exposure is not a breach of the data store. It is the model itself, deployed and queryable,
standing in as a channel to the data it learned from.

## Probing what the model remembers

*Membership inference, was this record in the training set*: A model often behaves a little
differently on data it was trained on than on data it has never seen: more confident, lower loss, a
sharper response. An attacker who can measure that difference can ask, for a given record, whether it
was part of training. When membership itself is sensitive, that someone was in a cohort of patients,
defaulters, or flagged users, the answer is the disclosure.

*Model inversion, reconstructing the input*: Given enough access to a model's outputs and a target
label or identity, an attacker can search for the input that most strongly drives that output,
recovering an approximation of a training example. Against models fitted on faces, records, or
documents, the reconstruction can be recognisable, rebuilding a sensitive input the model was never
meant to reveal.

*Attribute inference from partial knowledge*: An attacker holding some of a record's fields can use
the model to infer the rest, exploiting the correlations the model learned. The missing attribute,
a condition, an income band, a protected characteristic, comes out of the model's behaviour even
though it was never queried directly and never returned as an answer.

*Memorised secrets surfacing from a language model*: A language model fine-tuned on internal text can
reproduce verbatim fragments of that text when prompted in the right direction: a key, a name, a
snippet of a private document. The model is not retrieving a file; it learned the fragment well enough
to regenerate it, and a prompt that leans toward the memorised region can draw it back out.

*Confidence as a side channel*: Even a bare output can leak. The shape of a model's confidence across
many crafted queries carries information about what it was trained on, so a model that returns rich
scores hands the attacker a wider channel than one that returns a coarse decision. The side channel is
the same richness that makes the model useful.

Language models trained on sensitive text retain traces of that text in ways that may surface unexpectedly. A model does
not choose to memorise specific records; it fits patterns, and where the training data contains rare or highly specific
content, those patterns may sit closer to the surface than the designers intended. A hospital training on patient
records and publishing a query API creates exactly those conditions: structured data linked to identifiable individuals,
accessible through an interface that does not recognise privacy-targeted prompts as different from ordinary queries.
Questions anchored around unique demographic combinations, a rare blood type alongside a birth year and postcode, can
draw out associated records without the system flagging the prompt as an attack.

## Insider access and data exposure

### Classified AI queried by an authorised insider

An intelligence agency training an internal model on classified satellite imagery, communications intercepts, and field
reports and then granting analysts query access has created a channel between the classified corpus and everyone with
legitimate credentials. Extraction does not require stealing a file. A query framed around a specific facility, time
period, or named operation may surface the contents of documents the analyst was never authorised to read directly. The
attack is entirely within legitimate use patterns; the failure is that the model has blurred the access controls the
document system enforced.

### Internal communications memorised by a customer-service model

A company training a customer-service assistant on internal message threads, email correspondence, and support logs
transfers institutional memory into a queryable form. Questions anchored around specific individuals, dates, and
transactions may produce responses drawing on memorised message content rather than general knowledge. A confidential
discussion between named parties about a specific deal may surface accurately and in some cases verbatim. The model does
not distinguish between what was meant to be internal and what can safely be shared; it reproduces what it was trained
on.

### Attribute inference and synthetic profiling

A model trained on user posts, direct messages, and location data can be used to infer attributes of individuals in the
training set. An adversary combining membership inference, first establishing that a specific person was in the dataset,
with attribute inference to fill in fields not directly queried, can reconstruct a behavioural profile without ever
accessing an account. The reconstruction is statistical rather than verbatim, but it may be accurate enough for
personalised targeting or establishing leverage. Confirming that a specific person was in the training set is often
sufficient on its own: it establishes that they were a customer of that institution, a patient at that hospital, or a
member of that service, before any data content is recovered.

## Detection and mitigation limits

Removing sensitive data from training corpora before training is the obvious first step and an incomplete one. Models
retain traces of rare patterns more persistently than common ones, and identifying every sensitive fact across a corpus
large enough to be useful is not tractable. A record appearing once is more likely to be memorised precisely than one
appearing thousands of times; rarity is a risk factor, not a protection.

Removing rare data points to prevent memorisation makes the model less capable in exactly the areas where rare data
matters. A medical model trained without rare conditions becomes less useful for rare conditions. The trade-off is not
eliminable; it can only be managed.

Prompts designed to extract memorised content evolve faster than defences against them. A filter trained to block one
phrasing learns nothing about reformulations that achieve the same goal. The attack surface proliferates; the defensive
filters lag.

Differential privacy, adding calibrated noise to the training process, is the most principled technical response. It
provides formal guarantees about how much any individual record can influence the model's outputs. It also degrades
accuracy, more so for rare and sensitive classes, which tend to be the most clinically or operationally significant.
Some accuracy loss is usually accepted; how much is rarely decided with inference attacks explicitly in view.

A model is a database with a friendly face. The interface is more approachable and the data less directly addressable,
but the content remains, and the channel to it is open as long as the model is queryable.

## Minimising the data trace

Treating the training data's sensitivity as a property of the deployed model, not only of the data
store. A model fitted on personal data can carry obligations about that data wherever it is served,
and the regulatory framing of training data as personal data is still settling.

Limiting what the model reveals about its own certainty, since membership and inversion attacks feed
on the gap between seen and unseen data. Coarser outputs and calibration that narrows that gap give
the attacker less to measure.

Considering privacy-preserving training where the data warrants it, so that no single record leaves a
distinctive enough trace to be recovered. The aim is a model whose behaviour barely changes whether or
not any one record was included.

Watching for query patterns shaped like probing, repeated near-duplicate inputs, systematic sweeps
around a particular record or label, which distinguish an inference attack from ordinary use even when
each query looks benign.

## AI-generated zero-day with hallucinated CVSS scores

Google's Threat Intelligence Group identified the first confirmed AI-generated zero-day exploit.
The [Python script bypassed 2FA on a system administration tool](https://www.itpro.com/security/google-threat-intelligence-group-first-ai-zero-day-exploit-discovery)
and contained hallucinated CVSS scores alongside textbook-style comments, clear markers of LLM output. The inference
dimension here is that the attacker used a model trained on public vulnerability data to probe its knowledge of attack
patterns and generate a working exploit. The hallucinations were not a failure; they were a by-product of a process that
succeeded. The forensic signature, inflated severity scores and academic-register commentary, is what allowed
attribution to an LLM rather than a human author.

## Counter moves

The privacy view of membership and reconstruction is in the green notes on
[de-anonymisation](https://green.tymyrddin.dev/docs/threat-models/deanonymisation/); the security-operations view
is in the purple notes on [the identity layer](https://purple.tymyrddin.dev/docs/ai-security/identity/).

## Related

* [The identity layer](https://purple.tymyrddin.dev/docs/ai-security/identity/)
* [Threat register](https://purple.tymyrddin.dev/docs/audits/supportive/threat-register/)
* [De-anonymisation, the privacy view](https://green.tymyrddin.dev/docs/threat-models/deanonymisation/)
* [The calibration view](https://purple.tymyrddin.dev/docs/adversarial-ai/)
