# Reducing phishing exposure

There is no control that eliminates phishing. The honest framing is that the goal is to raise the cost
and lower the yield: make it harder to deliver lures, harder for users to interact with them without
a visible warning, and faster to detect and respond when something gets through. A layered approach
is the only realistic one, because any single layer has a bypass.

## Email authentication

SPF, DKIM, and DMARC are the three email authentication protocols that, when correctly configured
and enforced, prevent attackers from sending email that appears to originate from a domain the
organisation controls. All three are well understood and widely deployed. Their collective limitation
is that they only prevent spoofing of domains that implement them, and most phishing uses look-alike
domains rather than direct spoofing. They remain worth deploying correctly, because direct spoofing
of your domain is both technically trivial without them and completely preventable with them.

DMARC at enforcement policy (p=reject or p=quarantine) is the meaningful configuration. A DMARC
record at p=none generates reports but does not prevent anything. Many organisations have p=none
DMARC records and believe they have DMARC protection. They do not.

## Link and attachment inspection

Gateway tools that inspect URLs and detonate attachments in sandboxes catch a significant proportion
of commodity phishing campaigns. Their consistent gap is anything that routes around URL inspection:
QR codes, PDFs containing links, HTML attachments, and content hosted on trusted domains. Knowing
the gaps is useful both for understanding what the controls will and will not catch, and for setting
realistic expectations with stakeholders about what "email security" covers.

Rewriting URLs to proxy through inspection and rechecking them at time of click rather than at
delivery is more effective than delivery-time scanning alone, because many phishing pages go live
after the email is sent to avoid exactly that scan.

## Awareness training

Awareness training that consists of periodic phishing simulations followed by remedial content for
those who click has limited evidence of effectiveness and reasonable evidence of frustration among
recipients. It is not worthless, but its contribution is at the margin rather than at the core.

What works better is making the secure behaviour the easy behaviour: visible indicators when email
arrives from outside the organisation, clear and simple reporting mechanisms for suspicious messages,
and a response process that is fast enough that reporting feels useful rather than futile. If
employees who report phishing hear nothing for three weeks, they stop reporting.

Training that focuses on the specific pretexts relevant to the organisation's context is more
useful than generic awareness content. A finance team is targeted differently from an IT team.
The examples should match the actual threat.

## QR code handling

Organisational policy on QR code scanning is increasingly worth having explicitly. Mobile devices
that scan QR codes bypass URL inspection, do not have endpoint agents in most BYOD environments,
and may not be subject to web filtering. The control options are limited: MDM policies on corporate
devices can intercept scanned URLs, and user awareness about verifying QR code destinations before
interacting with them is more tractable than awareness about generic phishing, because the threat
is concrete and the behaviour change is simple.

## Techniques

- [Email phishing](../phishing/email.md) — spear phishing, BEC, domain construction, HTML smuggling
- [Quishing](../phishing/quishing.md) — QR code delivery and mobile device exposure
- [Vishing and callback phishing](../phishing/vishing.md) — helpdesk impersonation and callback phishing
- [Smishing](../phishing/smishing.md) — SMS lures and OTP interception

## Resources

- [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape)
- [DMARC.org](https://dmarc.org/)
