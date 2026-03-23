# Quishing

A QR code is a URL that cannot be read by a human and is not inspected by most email security tools.
It is printed as an image, which email gateways treat as an image rather than as a link, and it
requires a phone to decode, which means the actual access happens on a device that is frequently
outside the organisation's mobile device management and has no endpoint security installed.

Quishing is phishing via QR code, and it has become prevalent enough that it is now a standard
component of mature phishing campaigns rather than a novelty. The technique is particularly useful
when targeting environments with strong email link filtering, because the QR code is a straightforward
way to move the click from a monitored desktop browser to an unmonitored mobile one.

## QR codes in email and documents

The most common delivery format is a PDF attachment or an inline image in an email. The message
typically claims that an action is required: review and sign a document, complete a security
verification, access a shared file, or scan the code to confirm receipt. The pretext leans on
familiarity. QR codes appear legitimately in corporate communications for expense systems, building
access, and document signing workflows, so seeing one in a work context does not trigger the same
scepticism that a suspicious link might.

The payload is usually a credential harvesting page styled to match the expected service. A QR
code in an email that appears to come from IT asking the target to re-verify their Microsoft 365
credentials produces a page that looks like the Microsoft sign-in page, collects the username and
password, and redirects to the real Microsoft page while passing the stolen credentials to the
attacker.

## PDF-based delivery

QR codes embedded in PDFs are particularly effective because a PDF is a common and trusted document
format, the code appears as part of the document's visual design rather than as an obvious link,
and the instruction to scan it with a phone is built into the format. PDFs with embedded QR codes
appear in invoice fraud campaigns, fake policy documents, onboarding materials, and contract
reviews.

The operational advantage of PDF delivery is that it distances the phishing payload from the
initial email. The email itself may be entirely clean from a scanning perspective: it contains
a PDF, which contains an image, which when scanned produces a URL. Each step is a layer of
indirection away from the automated detection systems that would catch a plain malicious link.

## Physical quishing

QR codes in physical spaces are trusted precisely because they appear in contexts that feel
official: restaurant menus, parking meters, conference registration desks, visitor check-in
tablets. Replacing or covering a legitimate code with a malicious one requires a printed sticker,
a few seconds of unobserved time, and some prior knowledge of where the code is and what it
should lead to.

The replacement code leads to a page that superficially resembles what the user expected to see.
A parking payment code that redirects to a spoofed parking payment site collects card details
rather than parking charges. A conference check-in code that redirects to a credential collection
page styled to match the event registration system harvests credentials from attendees who have
no reason to be suspicious of a QR code at a conference they are already attending.

Physical quishing is difficult to detect because it requires someone to notice that a sticker
has been placed over the original code, and in most environments nobody is looking.

## Detection gaps

The reason quishing persists is structural. Email security tools are built around URL and
attachment inspection. A QR code is an image, and the URL it encodes is not present in any
form that current gateway tools reliably extract and analyse. Organisations that have invested
significantly in email security find that a QR code in a PDF reaches inboxes with the same
reliability as a clean internal message.

Mobile devices, which do the actual scanning, sit outside most corporate security stacks.
Bring-your-own-device environments are particularly exposed, because the personal phone that
scans the code has no corporate endpoint agent, no proxy forcing its traffic through inspection,
and no policy preventing it from visiting a phishing page.

## Runbooks

- [Runbook: Quishing campaign](../runbooks/quishing-campaign.md)
