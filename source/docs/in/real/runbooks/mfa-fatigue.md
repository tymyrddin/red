# Runbook: MFA push fatigue

MFA push fatigue exploits authenticator apps that present authentication requests as approve/deny
push notifications. An attacker with valid credentials generates repeated authentication attempts
against the target account. The target receives a stream of notification pop-ups. At some point,
some proportion of targets approve one to make the noise stop. That proportion increases
significantly when the attacker pairs the push bombing with a vishing call.

This technique requires valid credentials obtained by prior phishing or another means. It does
not require any technical capability beyond the ability to attempt logins.

## Objective

Authenticate to a target account protected by push-based MFA (Microsoft Authenticator, Duo,
Okta Verify, or similar) by exhausting the target's willingness to deny notifications.

## Prerequisites

- Valid credentials for the target account (username and password).
- Confirmation that the account uses push-based MFA rather than TOTP or FIDO2.
  Push MFA sends a notification to a phone app; TOTP requires typing a code. If you are not
  sure which is in use, a failed login attempt will tell you: push MFA shows "Check your
  authenticator app" without asking for a code entry.
- A VoIP number with a spoofable caller ID if vishing support is planned.
- The target's phone number (from OSINT or the target's organisation directory).

## Confirming MFA type

Attempt to authenticate with the stolen credentials. The login page response tells you what
second factor is expected:

- "Check the Microsoft Authenticator app on your phone" with no code field: push notification.
- "Enter the code from your authenticator app": TOTP. This playbook does not apply.
- "Use your security key": FIDO2. This playbook does not apply.
- "A text has been sent to your phone": SMS OTP. Consider SIM swap instead.

## Push bombing

Once push MFA is confirmed, begin authentication attempts in rapid succession. Each attempt
generates a push notification on the target's device. The notification asks the target to approve
or deny. Most targets will deny the first several and wonder why they are receiving unexpected
authentication requests. The goal is persistence, not speed: a notification every 30 to 60
seconds over an extended period is more effective than a burst, because it is harder to ignore
across an hour than across a minute.

Microsoft Authenticator with number matching enabled requires the target to enter a displayed
number before approving, which defeats simple push bombing. Check whether number matching is
in use before committing to this technique: if each push requires a number, the target will
see a number on the login page they didn't initiate and deny it.

## Vishing support

A vishing call substantially improves success rates by providing a reason for the notifications
and an instruction to approve them. The call should arrive during or immediately after the push
bombing phase begins.

Pretext: IT helpdesk responding to an account security alert.

Script outline:

"Hi, this is [name] from the IT security team. We're seeing some unusual activity on your
account, and we've triggered a verification process to lock it down. You should be getting an
authentication request on your phone now. Can you confirm you're receiving it? If you can just
approve that, we can get your account secured and I can walk you through the next steps."

The call provides an authority figure, a plausible explanation for the notifications, a specific
instruction, and a reason to act quickly. The target who approves under these circumstances has
been socially engineered, not tricked by a technical flaw.

If the target asks for a callback number to verify, have one ready: a VoIP number that matches
the organisation's main number, or a publicly listed IT helpdesk number that you have already
set up a voicemail on. The goal is to avoid the call ending before the approval is given.

## After approval

When the target approves a notification, you have approximately 60 to 90 seconds to complete
the authentication before the session token expires. The login page showing the pending
authentication request will complete and redirect to the authenticated session automatically
once the push is approved. Do not close the browser window during the push bombing phase.

Immediately after authentication:

1. Navigate to the account's security settings and review registered MFA devices and active sessions.
2. If the engagement scope allows persistence, add an authentication method (a phone
   number or an authenticator app you control) before the legitimate user notices the session and
   revokes it.
3. Export any evidence required by the scope: access to email, files, or administrative functions.

## Failure modes

The target changes their password: the credentials are now invalid. Requires returning to the
phishing phase.

The target contacts IT: if the organisation has a responsive security team, the account may be
locked within minutes of the report. The window between approval and detection is short in
well-run environments.

Number matching is enforced: push bombing without vishing will not succeed. Vishing can still
work if the caller instructs the target to enter a number displayed on their screen, but this
requires more precise coordination.

The target is unreachable by phone: push bombing alone, without vishing support, has a lower
success rate. Document the attempt and the account details for the report, and note whether
the account showed any rate limiting on authentication attempts.

## Evidence collection

- Screenshot or recording of the authentication attempt and successful login.
- Call log showing the vishing attempt (timestamp, duration, caller ID used).
- Screenshot of the authenticated session showing account access level.
- Notes on any rate limiting or account lockout behaviour observed.

## Techniques

- [Vishing and callback phishing](../phishing/vishing.md) — helpdesk impersonation and vishing support call
- [Smishing](../phishing/smishing.md) — SIM swap as alternative where push MFA is not in use
- [MFA bypass](../credentials/mfa-bypass.md) — push fatigue and SIM swap approaches

## Resources

- [Social Engineering Framework: Vishing](https://www.social-engineer.org/framework/attack-vectors/vishing/)
- [ElevenLabs voice synthesis](https://elevenlabs.io/)
- [COUNTERING SIM-SWAPPING (pdf)](https://www.enisa.europa.eu/sites/default/files/publications/ENISA_REPORT-Countering_SIM_Swapping.pdf)
- [Microsoft: Number matching in Authenticator](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match)
