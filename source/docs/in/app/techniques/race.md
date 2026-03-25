# Race conditions

Race conditions occur when an application reads a value, makes a decision based on it,
and then writes a result, but the gap between the read and the write is large enough for
a second concurrent operation to read the same unchanged value and make the same decision.
Both operations proceed based on a state that neither of them alone would have produced.

The classic form is the time-of-check/time-of-use gap: the application checks a condition
(sufficient balance, valid coupon, unredeemed token), and between the check and the write,
a second request makes the same check against the unchanged state and also passes.

## HTTP/2 and the single-packet attack

Race condition exploitation over HTTP/1.1 has always been theoretically possible but
practically unreliable: network jitter between requests widened the timing window unpredictably.
HTTP/2's multiplexing changed this. Multiple requests sent in a single TCP packet arrive
at the server simultaneously, because they are delivered by the same packet. The network
timing variance that made HTTP/1.1 races impractical is eliminated.

This means race conditions that previously required favourable network conditions to exploit
are now reliably reproducible. A balance check that takes ten milliseconds and was exploitable
perhaps one time in a hundred is now exploitable nearly every time with the right tooling.

Turbo Intruder's `race-single-packet-attack.py` template implements this: it queues all
requests and sends them in one TCP write. The server receives all of them before processing
any. The race window is now defined by server-side processing time alone.

## Target patterns

The most impactful race conditions occur in operations with economic or privilege consequences:

Balance depletion below the available amount: two concurrent requests against a balance of
one unit both pass the "balance sufficient" check and both execute the deduction. The result
is a spend of two units from a one-unit balance.

Single-use token reuse: two concurrent redemption requests for the same password reset token,
OTP, invite code, or coupon both pass the "token not yet used" check. Both redeem the token.
One redemption produces two effects.

Quota and rate limit bypass: concurrent requests against a daily usage counter each see the
pre-increment value. All of them pass the "quota not exceeded" check and all increment the
counter, producing a total that exceeds the permitted limit.

Inventory overselling: concurrent purchase requests for the last item in stock all see
"quantity: 1" and all confirm an order. More orders are confirmed than items exist.

## Race conditions in non-obvious places

Race conditions are not confined to financial operations. Any state transition that is
implemented as a read-check-write sequence rather than an atomic operation is a candidate.
Account status flags, permission grants, subscription activations, and verification status
updates have all been found vulnerable.

Asynchronous processing adds a distinct class of race condition: the request returns
immediately, but the actual operation happens in a background job. Two requests that each
trigger a background job may both complete their jobs based on the state that existed when
the jobs were created, not the state when each job runs.

## Portswigger lab writeups

- [Web shell upload via race condition](../burp/upload/7.md)

## Runbooks

- [Workflow and business logic testing](../runbooks/business-logic.md)
