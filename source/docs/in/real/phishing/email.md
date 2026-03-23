# Email phishing

Email phishing has been declared dead approximately every two years since 2005, and it continues to be
responsible for the majority of initial access in real-world intrusions. The reason is not that defenders
have failed to try. It is that the attack surface is a human being reading messages, and human beings
reading messages are difficult to patch.

The techniques have matured considerably. What passes for a phishing email now is a long way from the
Nigerian prince correspondence that trained the first generation of security awareness. Modern spear
phishing can be indistinguishable from legitimate internal communication, particularly when it is built
on thorough reconnaissance and delivered from a domain that has been warm for several weeks.

## Spear phishing

Generic phishing casts a wide net and accepts a low conversion rate. Spear phishing inverts that
trade-off: a small number of carefully selected targets receive messages tailored specifically to them,
with sufficient contextual accuracy that the plausibility is high even for people who would normally
be cautious.

The targeting information comes from reconnaissance: the target's name and role, their relationships
within the organisation, current projects they are involved with, recent events that would make
a particular message timely. A message about an invoice related to a vendor the target actually
works with, arriving at the end of a financial quarter, from a domain that closely resembles the
vendor's real domain, does not look like a phishing email to most people. It looks like an admin
problem that needs resolving.

## Business email compromise

Business email compromise is spear phishing with a specific objective: fraudulent financial
transactions, wire transfer requests, or payroll redirects. The target is usually someone with
authority to move money or change payment details, and the pretext is usually a request from
a senior colleague or a trusted external party.

What makes BEC distinctive is that it often requires no malware and no malicious link. The attack
is the email itself. A CFO asked by a message that appears to come from the CEO to make an urgent
transfer to a new account is being socially engineered, not technically exploited. The controls
that would catch a piece of malware are irrelevant.

BEC losses run into billions of dollars annually, which is a reasonable indicator of how effective
the approach remains. The organisations most vulnerable are those where financial processes depend
on email authorisation without independent verification channels.

## Domain and sender construction

A phishing email is more convincing when it arrives from a domain that resembles the real sender.
Typosquatting (targetco.com versus targetco.com, with a homoglyph substitution), subdomain spoofing
(mail.targetco.attacker.com), and look-alike domain registration (target-co.com, targetco-helpdesk.com)
all create sender addresses that are easy to miss at a glance. The address shown in an email client
is often the display name rather than the underlying address anyway, and display names can be set
to anything.

Warming a domain before use matters for deliverability. A domain registered the day before an
engagement has no sending history and is likely to be treated with suspicion by spam filters.
A domain registered several weeks earlier, used lightly for legitimate-looking traffic, and
configured with correct SPF, DKIM, and DMARC records is much more likely to arrive in the inbox
rather than the junk folder.

## AI-assisted lure generation

Generative AI has meaningfully lowered the cost of producing convincing phishing content. The
non-native speaker tells of poorly worded phishing emails are now largely irrelevant: a large
language model produces fluent, well-punctuated text in any register on request. More usefully,
it can generate content that matches the specific vocabulary and communication style of an
organisation, based on samples obtained during reconnaissance. Internal documents, public job
postings, and press releases all contain enough stylistic information to train a convincing
approximation of internal communications.

The volume benefit is also significant. Producing a hundred individually tailored spear phishing
messages now requires the time to run the prompts, not the time to write a hundred emails.

## HTML smuggling

HTML smuggling delivers a malicious payload via an HTML attachment or an inline blob in an email,
assembled in the browser from encoded JavaScript rather than transmitted as a recognisable file.
Because the malicious content does not exist as a file until the browser reconstructs it, it is
not present in the email for gateway scanning tools to inspect. The assembled file drops to the
downloads folder and the user opens it.

It is a technique that exploits the architectural gap between where email content is inspected
(the gateway) and where it executes (the browser), and that gap is not going away.

## Runbooks

- [Runbook: AiTM phishing with Evilginx2](../runbooks/aitm-phishing.md)


