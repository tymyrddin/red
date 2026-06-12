# Data and decision manipulation

Changing data or instructions so a system keeps running, keeps reporting healthy, and produces the
wrong outcome anyway. Nothing is encrypted or deleted; the target is the belief the victim acts on.
This is distinct from [business process attacks](business-process.md), which redirect money through
legitimate workflows, and from [destruction](destruction.md), which removes data outright. Two shapes
recur.

## Poisoning a feed to drive a decision

Where a victim trusts a feed, the cheaper attack is not to take the feed down but to lie to it.
Plausible false data, nested where no one looks, lets the victim discover a trend for itself and act
on it, and a thing discovered is believed more firmly than a thing asserted. Deepfaked sensor logs,
fabricated telemetry, and forged records all work the same way: they exploit the analyst's own
confidence rather than any technical control.

The value is leverage at a distance. A victim spending its own uncompromised resources on a
self-inflicted overreach has been moved further than any direct action could move it, and the clean
audit trail behind every step makes the manipulation hard to see and harder to undo.

```text
# the grooming, not the payload, is the work:
# - match the cadence, format, and noise of the genuine feed
# - leave the conclusion to be found, not stated
# - mind the tell forgers skip: timestamps and sequence that do not reconcile
```

## Tampering with automation and firmware

The other shape rewrites the instructions a machine runs from rather than the data it reports.
Config-as-code, controller logic, model inputs, and build artifacts are all instructions, and
altering them upstream, before they reach the thing that runs them, leaves every downstream unit
wrong at the moment it is made. Delivered through the supply chain, the tampered component arrives
signed and trusted.

Repository or build-level persistence is the hard version. Where the source a victim builds from is
corrupted, a patch pushed afterward does not reach a flaw that was in the material, and the fix is to
stop building and rebuild from a clean source, which is expensive enough that the corruption can sit
for a long time.

```text
# delivery routes that arrive trusted:
# - a poisoned dependency or build step, signed and in the pipeline
# - an "ethical" or "safety" update that is no such thing
# - a legitimate maintenance channel given one extra instruction
```

Detection is the weak point for both shapes. The inputs are valid, the certificates are real, and no
malware runs, so monitoring built for intrusion sees a system working rather than a system worked.
