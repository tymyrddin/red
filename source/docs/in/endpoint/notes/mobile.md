# Mobile exploitation

Mobile devices hold the same category of material as desktop endpoints: session tokens, cloud credentials, email, messaging history, and SSO state. They are also the primary MFA factor for many authentication flows, making them a target not just for data but for the authentication bypass they can provide. The attack surface is structurally different from desktop endpoints, but the objectives are the same.

## The modern mobile threat model

Commercial mobile surveillance software (NSO Group's Pegasus, Intellexa's Predator, and similar) has demonstrated that fully remote, zero-interaction mobile compromise is achievable at a price point accessible to nation states and well-resourced criminal groups. These exploit chains use zero-click vulnerabilities in message parsing, image rendering, and webkit to achieve kernel-level access without any user interaction beyond receiving a message. The techniques developed at the commercial tier trickle into the broader threat landscape over time.

Below the zero-click tier, one-click attacks via links delivered through SMS, WhatsApp, or email remain the dominant mobile delivery mechanism. The user taps a link that exploits a browser or WebKit vulnerability, then a privilege escalation chain achieves persistence. The window between delivery and user awareness is short; modern chains are designed to complete within seconds.

## iOS attack surface

iOS's security model centres on code signing and sandboxing: all executed code must be signed by Apple, and applications are isolated from each other and from the OS. Exploitation requires either a kernel vulnerability that bypasses these controls or abuse of legitimate iOS APIs.

Legitimate distribution channels for mobile device management profiles are a useful social engineering vector. An MDM profile installed by the user grants the MDM server broad control over the device: app installation, configuration enforcement, VPN routing, and email account management. A malicious MDM profile installs a supervised device relationship that the attacker controls.

iCloud credential theft provides access to device backups, iMessages, photos, and Find My location data. iCloud tokens extracted from a macOS device where the user is signed in (stored in the macOS keychain) or from the Windows iCloud application provide this access without any interaction with the iOS device itself.

## Android attack surface

Android's more open app installation model creates a larger attack surface for malicious app delivery. Sideloading enables installation outside the Play Store, and social engineering to install a "utility" or "security" app that requests extensive permissions is a reliable delivery mechanism in targeted scenarios.

Accessibility services granted to a malicious app provide comprehensive device control: reading screen content from all applications, injecting touch events, capturing screenshots, and intercepting SMS messages including OTP codes. Many Android banking trojans and commercial spyware use accessibility services as their primary capability layer.

ADB (Android Debug Bridge) exposed over TCP or accessible when USB debugging is enabled provides shell-level access to the device. Devices with USB debugging enabled and connected to untrusted charging stations or computers are vulnerable to ADB-based exploitation.

## MFA bypass via mobile

SIM swapping redirects the victim's phone number to an attacker-controlled SIM by social engineering the mobile carrier. Once the number is reassigned, SMS OTP codes, voice calls, and WhatsApp verification arrive on the attacker's device. The attack requires social engineering the carrier's support staff with enough personal information to pass their identity verification, which is usually available from data breach databases.

Push notification fatigue exploits multi-factor authentication implementations that use push notifications: the attacker, having already obtained the user's password, triggers repeated authentication prompts to the user's phone. Eventually the user approves a prompt to make the notifications stop. MFA prompt bombing has been used effectively against enterprise targets using Duo, Microsoft Authenticator, and similar platforms.

## Red team implications for mobile

Testing mobile security realistically means simulating delivery through the channels the user actually uses: SMS, WhatsApp, email links, and app store lookalikes. The objective is usually not to replicate a zero-click chain (which requires expensive vulnerabilities) but to evaluate whether the organisation's users would install a malicious profile or app, whether MDM controls would detect and remediate a compromise, and whether the mobile SSO token that results could pivot to corporate cloud resources.
