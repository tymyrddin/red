# Runbook: AiTM phishing with Evilginx2

Adversary-in-the-middle phishing captures session cookies in real time as the target authenticates
through a transparent reverse proxy. The result is a valid session token rather than just a
username and password, which means MFA is bypassed regardless of the second factor type, except FIDO2. 
This playbook covers the full setup from infrastructure to delivery to session extraction.

## Objective

Obtain a valid authenticated session for a target Microsoft 365, Google Workspace, or other
web application account, bypassing TOTP and push-based MFA.

## Prerequisites

- A Linux VPS with a public IPv4 address. Hetzner and OVH both work well from European infrastructure.
- A registered domain that is not brand new. Register it at least two weeks before the campaign
  and send a small volume of legitimate-looking email through it to build a sending reputation.
- DNS control for the domain (A records, MX, SPF, DKIM).
- Go installed on the VPS (1.21 or later).
- A phishing delivery mechanism: GoPhish, direct email, or a separate lure page that redirects
  to the Evilginx2 lure URL.
- Target email addresses from reconnaissance.

## Infrastructure setup

### Install Evilginx2

```bash
apt update && apt install git
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make
```

Ports 80 and 443 must be open and nothing else must be listening on them. Evilginx2 handles
its own TLS via Let's Encrypt.

### Configure the domain

```text
config domain phish.yourdomain.com
config ipv4 <your VPS IP>
```

Evilginx2 will request a Let's Encrypt certificate automatically when you enable a phishlet.
The certificate request will fail if the DNS A record for the phishlet hostname does not already
point at the VPS.

### Configure and enable a phishlet

Evilginx2 ships with phishlets for Microsoft 365, Google, and others. Check the phishlets
directory for what is available and maintained.

```text
phishlets hostname microsoft365 login.phish.yourdomain.com
phishlets enable microsoft365
```

Enabling the phishlet triggers the certificate request. Once the certificate is issued, the proxy
is live. Test by visiting the lure hostname in a browser: you should see the real Microsoft login
page, served from your domain.

### Create a lure

```text
lures create microsoft365
lures get-url 0
```

The lure URL is what you deliver to targets. When a target visits it, they are redirected to the
proxied Microsoft login page with a session tracking token embedded. All authentication traffic
passes through your VPS in real time.

## Phishing delivery

Set up GoPhish to send the lure URL to targets. The email pretext should give a plausible reason
for the target to authenticate: a shared document, a security notification, an expense approval
request. The lure URL should be masked behind a display link or a redirect through a clean
intermediate page to reduce the chance of it being blocked by email gateways.

If the target organisation uses Microsoft Defender for Office 365 with Safe Links, the lure URL
will be rewritten before delivery. Test delivery to an in-scope test account first and verify
the rewritten URL still reaches Evilginx2 correctly.

### Email sender setup

Configure the sending domain with:

```text
# SPF
yourdomain.com TXT "v=spf1 ip4:<VPS IP> -all"

# DKIM: generate with opendkim or use GoPhish's built-in key generation
# DMARC
_dmarc.yourdomain.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"
```

Start DMARC at p=none to avoid delivery failures during testing, then move to p=reject once
you have confirmed the configuration is correct.

## Session capture

When a target authenticates, Evilginx2 displays the captured session in the terminal:

```text
sessions
sessions <ID>
```

The session output includes the cookie string. Copy the full cookie value. In your browser,
open the target application, open developer tools, navigate to the cookies for the application
domain, and replace the session cookie value with the captured one. Reload the page. If the
session is still valid and has not been revoked, you are authenticated.

Session tokens for Microsoft 365 are typically valid for one hour for access tokens and up to
ninety days for refresh tokens, depending on the tenant's conditional access configuration. Act
quickly: some tenants revoke sessions immediately on password change or on detection of an
unusual sign-in.

## Conditional access considerations

Some tenants require that sessions originate from compliant devices or specific IP ranges
(conditional access policies). If this is in place, the captured session cookie will not work
from an arbitrary IP because the token is bound to device compliance state. Indicators of this
include being redirected back to a login page or receiving an access denied message despite
having what appears to be a valid session.

If conditional access is enforced, the session is still useful for demonstrating that credentials
and MFA were bypassed; document the conditional access barrier separately as a compensating
control.

## Evidence collection

Capture the following for the report:

- Evilginx2 session log showing the timestamp, target email, and captured token.
- Screenshot of the authenticated session in the target application.
- Email delivery confirmation from GoPhish showing which targets clicked the lure.
- Network diagram showing the proxy chain.

## Techniques

- [Email phishing](../phishing/email.md) — lure construction, domain warming, and delivery
- [MFA bypass](../credentials/mfa-bypass.md) — adversary-in-the-middle proxy mechanism
- [Credential harvesting via legitimate cloud services](../credentials/cloud-hosting.md) — alternative delivery infrastructure

## Resources

- [Evilginx2](https://github.com/kgretzky/evilginx2)
- [Modlishka](https://github.com/drk1wi/Modlishka)
- [GoPhish](https://getgophish.com/)
- [phishery](https://github.com/ryhanson/phishery)
- [SpecterOps blog: Microsoft phishing research](https://posts.specterops.io/)
