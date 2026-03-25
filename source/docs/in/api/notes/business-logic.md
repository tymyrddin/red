# Business logic abuse

Business logic abuse exploits what an API is designed to do, not a technical flaw in how it does
it. The API behaves exactly as specified. The attacker simply uses it in a sequence, at a scale,
or in a combination that the designer did not anticipate and the test suite did not cover.

This is now the primary battlefield for API attacks, because the defences against technical
vulnerabilities have improved and because business logic flaws are invisible to scanners.

## What changes when you think in systems

Point testing asks: does this endpoint behave correctly in isolation? Business logic testing asks:
what can someone achieve by using this system over time, across multiple sessions, and in
combinations the developer did not intend?

The answer is usually more than expected. APIs are built to handle the happy path. Edge cases,
race conditions, state transitions, and the behaviour of legitimate features at their limits are
tested less rigorously.

## Workflow abuse

Workflows are sequences of API calls that produce an outcome: a purchase, a refund, a content
upload, an account verification. Each step in the workflow moves the system through a state
transition. Workflow abuse exploits the state machine: skipping steps, replaying steps, running
steps in a different order, or forcing the system into an invalid intermediate state.

Refund loops: initiate a purchase, claim a refund, retain the goods, repeat. Some implementations
check the refund request against the order record but do not mark the order as refunded until after
the goods are released, creating a window for concurrent refund requests.

Credit and quota abuse: some APIs grant credits or quotas that replenish on a schedule. If the
replenishment check and the deduction are not atomic, concurrent requests can consume from the
same quota allowance before the deduction is recorded.

Free tier exploitation: features gated behind a paid tier sometimes have enforcement at the
frontend that the API does not replicate. Direct API calls bypass the tier check entirely.

## Chaining

Legitimate endpoints produce unintended outcomes when combined. The individual calls are all
authorised; the combination is not.

Password reset chains: a reset link sent to an old email address is still valid if the user
updated their email. Requesting a reset for account A, changing the email to an attacker-controlled
address, and then using the reset link sent to the original address can produce account takeover
using only documented, authenticated API calls.

Permission accumulation: some permission grants are additive and never audited for total effect.
Calling the role assignment endpoint for multiple overlapping roles that individually look harmless
may produce a combination with permissions the designer did not intend.

Export and import chains: upload content in one format, trigger a processing step, retrieve the
output in another format. The processing step may not validate the input as carefully as the
initial upload endpoint because it trusts internal data.

## Race conditions

Race conditions occur when two concurrent requests access shared state between the read and the
write. The application reads the current value, both requests see the pre-modification value, both
write based on what they read, and one write is lost while the other takes effect at the wrong
baseline.

The classic case is concurrent requests against a balance check: both requests pass the balance
check because neither has yet written the deduction, then both proceed to the spend operation,
resulting in a spend that exceeds the available balance.

Modern HTTP/2 and HTTP/3 allow multiple requests to be sent in a single packet, eliminating the
network timing variance that makes race condition exploitation difficult over HTTP/1.1. This makes
previously impractical race conditions reliably reproducible.

## Why it is hard to detect and defend

Business logic abuse looks like normal usage. Each individual API call is authenticated, authorised,
and within the documented parameter ranges. Anomaly detection based on request volume or error
rates produces no signal. Detection requires understanding what normal workflows look like and
identifying deviations in sequence, frequency, or outcome.

The defender's disadvantage is that defining "normal workflow" precisely enough to detect deviations
requires the same understanding of the business logic that the attacker exploited.

## Runbooks

- [Business logic testing](../runbooks/business-logic.md)
- [Race condition testing](../runbooks/race-conditions.md)

## Playbooks

- [Business logic abuse](../playbooks/business-logic-abuse.md)
