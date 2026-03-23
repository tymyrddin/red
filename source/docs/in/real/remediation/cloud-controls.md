# Controlling cloud storage and OAuth exposure

The controls for cloud-hosted phishing and OAuth abuse are less mature than email security controls,
partly because the threats are newer and partly because the mechanisms that make them possible are
also the mechanisms that make legitimate cloud collaboration work. Restricting them requires
accepting some friction.

## Tenant restrictions

Microsoft 365 and Google Workspace both support tenant restriction policies: network-level controls
that prevent authentication to tenants other than your own (and a defined allowlist of trusted
partners) when traffic passes through a corporate proxy or Secure Web Gateway. An employee whose
web traffic is proxied cannot authenticate to an arbitrary M365 tenant, which prevents both
cloud-hosted phishing delivery and the use of personal accounts on corporate devices.

Tenant restrictions require that traffic pass through a controlled proxy, which makes them
effective for managed devices on the corporate network and less effective for unmanaged devices
or traffic that bypasses the proxy. The coverage is meaningful but not universal.

## OAuth application governance

Restricting which OAuth applications users can consent to is one of the higher-value controls
against consent phishing. In Microsoft 365, administrator consent can be required for all
applications or for applications requesting high-risk permissions, preventing users from
authorising third-party apps without review. In Google Workspace, equivalent controls exist
through the API controls section of the admin console.

Requiring administrator consent does not prevent the attack; it moves the target from an
individual user to an administrator who must be convinced that the application is legitimate.
That is a smaller and (in principle) more security-aware population, and the consent review
process provides an opportunity to examine what permissions the application is actually requesting.

Reviewing existing OAuth application authorisations periodically reveals applications that
were consented to historically and are no longer in use, applications with broad permissions
that were granted without scrutiny, and in some cases applications that were consented to
during a previous social engineering incident and never removed. This review is often deferred
because it is tedious; the tedium is the reason it is worth doing.

## Anonymous access controls

SharePoint and OneDrive sharing policies that permit anonymous access, files accessible to anyone
with the link without authentication, are the mechanism that makes much cloud-hosted phishing
viable. A policy requiring that shared content can only be accessed by authenticated users from
trusted tenants removes the most convenient delivery mechanism, though it does not address
content hosted on attacker-controlled tenants.

External sharing restrictions can be implemented at the tenant level, the site level, and the
file level, with more granular policies requiring more administrative overhead. The baseline
control worth implementing is preventing anonymous link creation; from there, tightening
external sharing to specific domains or disabling it for sensitive document repositories is
proportionate to the data classification of the content.

## Monitoring and detection

Useful monitoring signals for cloud-hosted attacks and OAuth abuse include: new OAuth applications
consented to by users, applications consented to with high-privilege scopes, sharing links
created for large numbers of files in a short period, authentication tokens being used from
IP addresses that have never been seen for that account, and API access patterns that differ from
the user's normal interactive behaviour.

None of these signals are intrinsically malicious. All of them warrant investigation when they
appear in combination or outside expected patterns.

## Techniques

- [Credential harvesting via legitimate cloud services](../credentials/cloud-hosting.md) — SharePoint, Google Drive, and cloud platform abuse
- [Consent phishing and OAuth abuse](../credentials/consent-phishing.md) — OAuth application registration and token persistence

## Resources

- [Microsoft: Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [Microsoft: Tenant restrictions](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tenant-restrictions)
- [Google: Control which third-party apps access Google Workspace data](https://support.google.com/a/answer/7281227)
- [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape)
