# Vishing and callback phishing

A phone call bypasses most of the controls that organisations have spent the last decade building
around email. There is no URL for a proxy to inspect, no attachment for a sandbox to detonate, no
domain for a threat feed to flag. There is a human voice asking a question, and the target has
about two seconds to decide whether to answer it.

Voice-based social engineering has been a staple of red team toolkits for as long as there have been
telephones, but it has developed considerably in the past few years. AI voice synthesis has made it
possible to replicate specific voices convincingly, and callback phishing has emerged as a hybrid
technique that combines the deliverability advantages of email with the conversion advantages of a
live call.

## Helpdesk impersonation

IT helpdesk impersonation is the most common vishing pretext in enterprise environments, for the
straightforward reason that the helpdesk is the one function that employees expect to call them
with questions, ask for credentials, and request that they take actions on their machines. A call
from "IT support" carries implicit authority, creates urgency through the suggestion of a problem
that needs resolving, and provides a natural justification for asking about system access.

A caller claiming to be from the helpdesk investigating unusual activity on an account will typically
ask the target to confirm their username, describe what they can see on screen, or open a specific
page while the caller "runs a diagnostic." All of these produce information or access. The target
who cooperates fully with an apparently legitimate support call has not made a poor decision by the
standards of the social contract they are operating in.

## Callback phishing (TOAD)

Telephone-oriented attack delivery is a phishing technique in which the initial lure is an email
that contains a phone number rather than a link. The email typically claims that a subscription
has been renewed, a charge has been applied to an account, or that urgent action is required. The
instruction is to call the provided number if you did not authorise the transaction.

The advantage over a standard phishing email is that no malicious URL is present, so gateway
scanning has nothing to detect. The conversion happens on the phone: when the target calls, they
speak to an attacker posing as customer service who walks them through steps that deliver the actual
payload, whether that is installing a remote access tool for "refund processing," visiting a
specific URL, or providing credentials to "verify the account."

Callback phishing campaigns have targeted corporate environments effectively because the email
format (invoice, subscription notification, software renewal) fits naturally into business contexts,
and employees who receive something that looks like an unexpected business charge tend to call
rather than delete.

## AI voice cloning

Synthetic voice generation has reached a point where a convincing impersonation of a specific
individual can be produced from a few minutes of source audio, most of which is publicly available
for anyone in a senior enough role. Conference talks, media interviews, investor calls, and webinars
all provide enough material to produce a voice model that is indistinguishable from the original in
a short phone call.

In practice this has been used for BEC-style attacks where the "CEO" calls a finance team member
to confirm a wire transfer, for verifying SIM swap requests at mobile carriers, and for bypassing
voice authentication systems at banks and brokerages. The latter are particularly vulnerable because
they were designed for the threat model of someone guessing a voice passphrase, not synthesising it.

## Operational considerations

Vishing works best with preparation. Know the name of the person you're calling, have a plausible
reason for the call that fits their role, and have a response ready for the questions that will
inevitably be asked. Spoofing the caller ID to show an internal extension or a number that matches
the claimed organisation removes one of the more obvious reasons a target might be sceptical.

Keep calls short. The longer a vishing call runs, the more opportunities there are for the target
to become suspicious, to look something up, or to suggest that you call back after they have spoken
to someone else. Get what you need and close the call before the situation has time to degrade.

## Runbooks

- [Runbook: MFA push fatigue](../runbooks/mfa-fatigue.md) — the vishing support call is the centrepiece of that playbook
