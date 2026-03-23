# Consent phishing and OAuth abuse

OAuth consent phishing obtains persistent access to a target's cloud account without ever learning
their password or intercepting their MFA code. It does this by convincing the target to grant
permissions to a malicious application through the same mechanism they use to grant permissions
to legitimate ones. The result is an access token that works until it is revoked, survives password
resets, and provides exactly as much access as the permissions the target approved.

The technique exploits something that was designed as a security improvement: OAuth's delegation
model, which allows users to grant applications specific, scoped access to their accounts without
sharing credentials. The model is sound. The problem is that most users approve OAuth permission
requests without reading them.

## How consent phishing works

The attack begins with a link that initiates a legitimate OAuth authorisation flow against Microsoft,
Google, or another identity provider. The application requesting authorisation is registered by the
attacker, but registered applications are not vetted for legitimacy before they can request permissions.
Any account with access to the Microsoft Azure portal or the Google Cloud console can register an
application and configure what permissions it will request.

When the target follows the link, they are redirected to a genuine Microsoft or Google login page.
If they are already authenticated, they skip the login and proceed directly to the consent screen.
The consent screen shows what permissions the application is requesting, in language that is often
vague enough to be unintentionally accurate: "Read your files," "Read your email," "Access your
contacts." The target clicks "Accept."

At that point the attacker's application has an OAuth token granting the approved permissions, and
the target's account is accessible for as long as the token is valid and the application remains
authorised. Revoking the access requires the user or an administrator to explicitly remove the
application from the account's authorised apps, which does not happen automatically when the
password changes.

## Phishing for consent

The lure that delivers the OAuth link needs to create a plausible reason to authorise the application.
Common pretexts include: a productivity tool that integrates with the target's email calendar, a
document signing service that needs access to OneDrive, a security application that needs to review
account activity, or a service the target's organisation has apparently deployed and requires
employees to connect.

The named application in the consent dialogue can be set to anything, including "IT Security Scanner,"
"Microsoft Compliance Tool," or whatever name makes the permission request seem routine. The displayed
name is not validated against any known application registry.

Corporate environments are particularly exposed because users are accustomed to connecting third-party
tools to their work accounts and are often encouraged to do so. An email that appears to come from IT
announcing a new integration and asking employees to authorise it is indistinguishable from the
legitimate version without examining the OAuth application's actual registration details.

## Scope and persistence

The value of a consent phishing attack lies in the combination of the permissions obtained and the
persistence of the access. Commonly requested scopes include Mail.Read (read all email),
Files.ReadWrite.All (read and modify all files), and Contacts.Read (read the full address book).
Calendars.Read reveals travel schedules and meeting patterns useful for targeting. Mail.Send allows
sending email as the compromised user, enabling further BEC-style attacks from a legitimate account.

Because the access is granted through a legitimate mechanism, it does not trigger password-based
anomaly detection. Signing in with a stolen password from an unusual location may generate an alert.
An authorised application accessing mail via the API does not look anomalous: it looks like an
integration working as intended.

## Tenant-wide compromise

In Microsoft 365 environments, an administrator who approves an application grants it tenant-wide
access rather than account-level access. A consent phishing attack targeting an Azure AD global
administrator who approves an application with the right permissions provides access to all accounts
in the organisation, not just the administrator's own. This is a relatively rare but high-impact
variant that has been used in targeted attacks against organisations running complex M365 deployments.

## Runbooks

- [Runbook: OAuth consent phishing](../runbooks/consent-grant.md)
