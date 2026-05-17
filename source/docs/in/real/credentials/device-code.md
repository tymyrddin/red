# Device code phishing

The device authorisation grant was designed for input-constrained devices: smart televisions, command-line
tools, hardware terminals that cannot open a browser. Rather than authenticate on the device itself, the
user is directed to a separate, capable device, where they visit a well-known URL, enter a short pairing
code, and complete authentication normally. The requesting device polls until it receives a token.

The attack uses this flow without modification. The target authenticates on a real Microsoft or Google page,
enters a real code, and approves a real request. Nothing in the protocol misbehaves. The attacker receives
a real token.

## How the flow works

The attacker calls the identity provider's device authorisation endpoint and receives two values: a
`device_code` for their own polling loop, and a short `user_code` to send to the target. The `user_code`
is typically eight characters, grouped as two four-character strings: `GVZF-PXHQ`, for instance.

The lure email tells the target to visit `microsoft.com/devicelogin` (or `google.com/device`) and enter
the code to complete a routine IT action: MFA registration, a compliance tool onboarding, a device
enrolment. Both URLs are legitimate identity provider pages. The email contains no phishing domain, no
proxy, no spoofed login form.

The target enters the code and authenticates. From their perspective, the experience is indistinguishable
from a normal Microsoft or Google sign-in. The attacker, polling in the background, collects an access
token and a long-lived refresh token when the target approves.

## What the attacker obtains

The refresh token is the useful artefact. In Microsoft Entra ID, refresh tokens for certain client
configurations remain valid for up to ninety days and are renewed on use, making them functionally
persistent. A password reset does not invalidate existing refresh tokens unless an
administrator explicitly revokes all sessions. An attacker who obtains a refresh token retains access
through a password change that the target believes resolved the problem.

Scope depends on the client used to initiate the device authorisation request. Tooling exists to
initiate the flow with Microsoft Graph API permissions broad enough to read mail, enumerate users,
and access SharePoint, all without registering an application in the target tenant.

## Why conditional access may not block it

Consent phishing is frequently blocked by conditional access policies that require application
authorisation to come from a managed or compliant device. Device code phishing does not trigger
those policies in the same way, because the authentication event is legitimate and the device
registration step never happens. In environments that have hardened against consent phishing,
device code flows are sometimes the path of less resistance.

## Timing and lure construction

The `device_code` typically expires in fifteen minutes, which imposes an urgency requirement on
the lure. Pretexts that work well are those that imply an expiring action: a registration window
closing, a provisioning step that times out, an onboarding sequence that requires completion
before a specified time. A target who believes they have a few hours will procrastinate; a target
who believes the window closes shortly is more likely to act immediately.

Common lure framings include IT provisioning emails, MFA re-registration requests following a
supposed security event, compliance tool onboarding, and device enrolment for a new access policy.
The legitimate URL is an asset: it removes the most common reason a careful target hesitates.

## Differences from consent phishing

In a consent phishing attack, the target approves an application's request for specific delegated
permissions. A consent screen lists what is being requested: "Read your files", "Send email on your
behalf". The target is making an explicit authorisation decision, even if they do not read what they
are approving.

In a device code attack, the target is completing a device pairing. There is no application
permission consent step in the standard flow. The target is not approving a delegation; they are,
from their perspective, logging in. The detection signatures are different: consent phishing leaves
a record of a new application authorisation event; device code phishing leaves a record of a
successful sign-in from an unrecognised device.

## Runbooks

- [Runbook: Device code phishing](../runbooks/device-code-phishing.md): full operational procedure from device code request through token extraction
- [Runbook: AiTM phishing with Evilginx2](../runbooks/aitm-phishing.md): for comparison with the proxy-based approach to token capture
- [Consent phishing and OAuth abuse](consent-phishing.md): the consent flow variant and how the token persistence model differs
