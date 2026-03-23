# Smishing

SMS is a channel that organisations mostly do not protect and users mostly do not distrust. Email has
acquired a reputation for phishing over two decades of awareness campaigns. SMS has not, and attackers
have noticed. Click rates on SMS lures are significantly higher than on email equivalents, partly because
mobile users are in motion and not looking closely, and partly because the medium itself still carries
an implicit assumption of legitimacy.

The technical barriers to sending SMS are low. Bulk SMS platforms are legitimate commercial services
used by every bank, delivery company, and appointment system, and they are easy to misuse. Sender IDs
can be set to alphanumeric strings rather than phone numbers, making the apparent source "DVLA" or
"NatWest" or whatever the campaign requires.

## Delivery and parcel lures

Fake delivery notifications are the dominant smishing format in consumer-facing campaigns and translate
well into corporate environments. A message informing an employee that a delivery requires action,
with a link to "reschedule" or "confirm address," is timely, plausible, and creates enough low-grade
urgency that most people do not examine the URL before tapping it. Corporate environments have high
volumes of deliveries, including equipment, documents, and catering, which increases the base rate of
legitimate messages the fake one is hiding among.

## OTP and account security lures

Messages claiming to be from IT, HR systems, or corporate SSO platforms about an account that requires
verification are effective in enterprise environments. The message creates a mild threat (your account
may be locked, your session has expired, unusual activity was detected) and a simple resolution (tap
this link and confirm your identity). The link leads to a credential harvesting page styled to match
the expected system.

Timing these messages to coincide with a known organisational event improves conversion rates. The
start of a new financial year, a recently announced system migration, or a security awareness campaign
that employees have been told to expect all provide context that makes a request for authentication feel
routine rather than suspicious.

## SIM swap preparation

SMS is also relevant as a target rather than a delivery mechanism. SMS-based two-factor authentication
routes codes through the mobile network, which can be subverted via SIM swapping: convincing a mobile
carrier to transfer a target's number to an attacker-controlled SIM. The social engineering in a SIM
swap is directed at the carrier's customer service team rather than the target themselves, and the
required information, name, address, account number, and sometimes a partial answer to a security
question, is often obtainable from data breaches or OSINT.

A successful SIM swap intercepts all SMS traffic to the target's number, including authentication codes,
password reset links, and bank notifications, for as long as the swap remains in place.

## iMessage and RCS

Apple's iMessage and Google's RCS both carry link previews and present messages with a visual richness
that makes lures easier to style convincingly. Neither is inherently more secure than SMS against a
recipient who taps a malicious link. Both are increasingly used as delivery channels for smishing
campaigns targeting high-value individuals, because they work over Wi-Fi and do not require an
active mobile network connection.

## Runbooks

- [Runbook: MFA push fatigue](../runbooks/mfa-fatigue.md) — SIM swap removes the second factor, making the fatigue approach unnecessary; the two techniques are alternatives depending on MFA type
