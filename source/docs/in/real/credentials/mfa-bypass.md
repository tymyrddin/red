# MFA bypass

Multifactor authentication has significantly raised the cost of credential theft. A stolen username
and password no longer provides access to an account that requires a second factor. This is genuinely
good news for defenders, and it has genuinely changed attacker behaviour in response. Rather than
accepting that MFA cannot be bypassed, attackers have developed a range of techniques for bypassing
it that are now standard components of phishing and social engineering campaigns.

The common thread across these techniques is that they target the human and process elements of
authentication rather than the cryptographic ones. MFA implementations are largely secure at the
mathematical level. They are less secure at the level of how humans interact with them, how they
are enrolled, and how they are reset.

## Adversary-in-the-middle proxy

The most technically complete MFA bypass for password-plus-TOTP authentication is a reverse proxy
that sits between the target and the legitimate service. The target interacts with what appears to
be the real service: they see the real login page, enter their real credentials, and complete the
real MFA challenge. The proxy forwards everything to the real service, which validates it and
returns a session. The proxy captures that session cookie.

Tools like Evilginx2 and Modlishka implement this approach. The target's browser is always talking
to the attacker's server, which proxies the connection to the real service in real time. From the
target's perspective the authentication succeeded normally. From the attacker's perspective they
now have a valid session token that they can use from their own browser until the session expires
or is revoked.

This technique is effective against TOTP-based MFA (the six-digit codes), email-based OTP, and
push notification approval. It is not effective against FIDO2 hardware tokens and passkeys, which
bind the authentication cryptographically to the specific origin URL and will refuse to authenticate
against a proxy regardless of how convincing the proxy looks.

## MFA push fatigue

Authenticator apps that send push notifications to mobile devices operate on the assumption that
the user will approve only notifications they recognise. In practice, if a user receives enough
notifications, particularly in quick succession or at inconvenient times, some proportion will
tap "Approve" to make the notifications stop.

Push bombing, or MFA fatigue, involves generating repeated authentication requests against an
account whose credentials are known. The requests appear as approval notifications on the target's
phone. An attacker who supplements the bombing with a vishing call ("This is IT support, we're
seeing an issue with your account, please approve the notification that's about to come through")
dramatically increases the success rate by providing a plausible explanation that removes the
target's reason to hesitate.

Several high-profile breaches have been attributed to this technique, including against organisations
with mature security programmes, which is a useful data point when advising clients about the
adequacy of push-based MFA.

## Real-time OTP relay

For TOTP-based authentication, real-time relay attacks capture the time-limited code during a live
phishing session. The target enters their credentials and OTP on a harvesting page. The attacker,
monitoring the incoming data in real time, immediately uses the credentials and OTP against the
real service before the thirty-second window expires. The target is redirected to the real site;
the attacker is now authenticated.

This requires a degree of operational choreography but is not technically complex. Purpose-built
phishing frameworks handle the relay automatically, alerting the attacker when fresh credentials
arrive and submitting them without manual intervention.

## SIM swapping

SMS-based OTP is vulnerable to SIM swapping: convincing the target's mobile carrier to transfer
their phone number to a SIM controlled by the attacker. All SMS messages, including authentication
codes, are then delivered to the attacker's device. The social engineering target in this case is
the carrier's customer service team, who can be convinced with information that is typically
obtainable from data breaches or social media: name, address, partial account details, and in
some cases just the last four digits of a payment card.

SMS MFA has been formally deprecated as a security control by NIST in its guidance, but it
remains widely deployed because it is easy to implement and familiar to users. For any account
that uses it, the security of the second factor is ultimately the security of a customer service
conversation at a mobile carrier.

## MFA reset and enrolment abuse

Recovery processes for MFA are often weaker than the MFA itself. An attacker who can convince
a helpdesk to reset MFA on an account, or who can trigger a self-service recovery process using
information obtained through OSINT or elicitation, bypasses the second factor entirely without
needing to attack it directly.

Enrolment windows are also a target. Accounts that have been created but not yet had MFA enrolled
are vulnerable to an attacker enrolling their own device first. Monitoring for new accounts or
recently reset MFA enrolments is a useful defensive indicator; exploiting that window is the
corresponding offensive technique.

## Runbooks

- [Runbook: AiTM phishing with Evilginx2](../runbooks/aitm-phishing.md) — covers the adversary-in-the-middle proxy approach end to end
- [Runbook: MFA push fatigue](../runbooks/mfa-fatigue.md) — covers push bombing with vishing support
