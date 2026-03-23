# MFA hardening

Not all multi-factor authentication is equal, and the gap between the weakest and strongest
implementations is the gap between a control that is bypassed routinely in phishing campaigns
and one that is not. Understanding the distinction is essential for making a recommendation
that will actually hold up when tested.

## Phishing-resistant MFA

FIDO2 hardware tokens and passkeys are the only forms of MFA that are technically resistant to
adversary-in-the-middle proxy attacks. The reason is that they bind the authentication response
cryptographically to the origin URL. A passkey registered to login.microsoftonline.com will not
authenticate against an Evilginx proxy, because the proxy's domain is not microsoftonline.com
regardless of how convincing it looks. The cryptographic check happens before the user does
anything, and it cannot be socially engineered.

Hardware security keys (YubiKey, Google Titan, and similar) implementing FIDO2 provide the
same binding property from a physical device. They are currently the strongest broadly deployable
MFA option and should be the recommendation for high-value accounts: administrators, finance
teams with payment authority, and anyone whose access to cloud environments would be meaningful
to an attacker.

Passkeys stored in platform authenticators (Face ID, Windows Hello) provide equivalent
phishing resistance when properly implemented and are increasingly available across consumer
and enterprise platforms. The enrolment experience is substantially better than hardware tokens,
which helps with deployment at scale.

## TOTP and push notifications

Time-based one-time passwords and push notifications are significantly better than no MFA and
significantly worse than FIDO2. Both are vulnerable to real-time relay attacks and push-based
approaches are additionally vulnerable to MFA fatigue. Deploying them is still worthwhile as a
baseline, particularly for accounts where FIDO2 deployment is not yet feasible, because they
raise the cost of account compromise even if they do not eliminate it.

If push notifications are in use, enabling number matching (the user must confirm a number
displayed on the authenticator rather than simply approving a notification) largely eliminates
push fatigue attacks. This feature is available in Microsoft Authenticator, Duo, and others
and should be enabled universally.

SMS OTP should be considered a legacy control and avoided for new deployments. The attack
surface it presents through SIM swapping, SS7 abuse, and carrier social engineering is
substantial enough that the convenience it offers is not a reasonable trade-off for most
organisations.

## Conditional access and anomaly detection

MFA is most effective as part of a conditional access policy that evaluates context, not just
credential validity. An authentication from an unfamiliar device, an unusual geography, or
outside normal hours should require step-up verification or trigger review rather than proceeding
normally. A stolen session token or compromised account will often be used in conditions that
differ from the legitimate user's patterns, and those anomalies are detectable if the controls
are in place to detect them.

## Techniques

- [MFA bypass](../credentials/mfa-bypass.md) — AiTM proxy, push fatigue, OTP relay, and SIM swap
- [Smishing](../phishing/smishing.md) — SIM swap and SMS OTP interception
- [Vishing and callback phishing](../phishing/vishing.md) — vishing-assisted push fatigue

## Resources

- [FIDO Alliance](https://fidoalliance.org/)
- [Microsoft guidance on phishing-resistant MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [COUNTERING SIM-SWAPPING (pdf)](https://www.enisa.europa.eu/sites/default/files/publications/ENISA_REPORT-Countering_SIM_Swapping.pdf)
- [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape)
