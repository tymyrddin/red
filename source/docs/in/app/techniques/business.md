# Application logic errors

Business logic vulnerabilities exploit what an application is designed to do, not a
technical flaw in how it does it. Each individual request is authenticated, authorised,
and within documented parameter ranges. The vulnerability lives in the state machine: in
the gap between what the developer tested and what the application actually does when used
in sequences, at scale, or in combinations they did not anticipate.

These vulnerabilities are invisible to scanners, produce no anomalous HTTP responses, and
are frequently missed by security reviews that test endpoints in isolation. Finding them
requires understanding the application's intended behaviour and then systematically probing
the edges.

## Thinking in workflows, not requests

A request is a point. A workflow is a path through the application's state machine. The
vulnerabilities worth finding are the transitions the developer tested less carefully:
the edge case where an order in "cancelled" state can still be refunded, the step in the
checkout flow that was never designed to be called without the prior step, the quota check
that runs before the deduction but does not hold a lock on the counter.

Mapping the workflow first answers the question that matters: what is the most valuable
terminal state reachable from my current position, and which paths to it are less
carefully guarded than the intended one?

## Common patterns

Step skipping is among the most consistently present findings. A multi-step workflow
that validates the user's eligibility at step one but does not re-validate at the final
confirmation step allows an ineligible user to complete the workflow by skipping to the
end. Eligibility checks implemented in frontend routing and re-checked only at the UI
display layer are entirely absent at the API layer.

Parameter trust across steps is a related pattern. A value set at step one and carried
forward in a session cookie, hidden form field, or query parameter may be modifiable
between steps. A price set at the "add to cart" step and carried forward to the "confirm
payment" step without server-side re-validation can be modified to any value the user
chooses.

Race conditions in check-and-write operations allow multiple concurrent requests to all
pass the same condition before any of them writes the result. A balance deduction that
reads the current value, confirms it is sufficient, and then writes the reduced value
is vulnerable to concurrent requests that all read the pre-deduction value and all
conclude the balance is sufficient. The result is a spend that exceeds the available
balance.

Chaining legitimate operations into unintended outcomes requires no single vulnerable step.
Two endpoint calls that are individually authorised can combine to produce an outcome
neither was designed to enable: a password reset flow combined with an email change
producing an account takeover, a role assignment endpoint called repeatedly for overlapping
roles producing privilege accumulation, an export endpoint that applies looser validation
to already-imported data.

## Why it is hard to detect

Business logic abuse looks like normal usage. Applying a slight escalation to rate or
frequency is the only distinguishing feature, and only then if someone is watching for it.
The defender's problem is that defining "normal workflow" precisely enough to detect
deviations requires the same understanding of the business logic that the attacker
exploited.

## Portswigger lab writeups

- [Excessive trust in client-side controls](../burp/business/1.md)
- [High-level logic vulnerability](../burp/business/2.md)
- [Inconsistent security controls](../burp/business/3.md)
- [Flawed enforcement of business rules](../burp/business/4.md)
- [Low-level logic flaw](../burp/business/5.md)
- [Inconsistent handling of exceptional input](../burp/business/6.md)
- [Weak isolation on dual-use endpoint](../burp/business/7.md)
- [Insufficient workflow validation](../burp/business/8.md)
- [Authentication bypass via flawed state machine](../burp/business/9.md)
- [Infinite money logic flaw](../burp/business/10.md)
- [Authentication bypass via encryption oracle](../burp/business/11.md)

## Runbooks

- [Workflow and business logic testing](../runbooks/business-logic.md)
