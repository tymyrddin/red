# Playbook: Endpoint compromise and identity pivot

This playbook connects the endpoint runbooks into an operational sequence. The chain runs from initial access through EDR evasion to credential harvesting, then off the device entirely into cloud and SaaS access. The endpoint is the starting point, not the objective.

## Objective

Demonstrate that a phishing delivery or client-side exploitation scenario translates to access to the organisation's cloud resources and SaaS platforms, using the endpoint's stored identity material to move laterally without remaining on the device.

## Prerequisites

- Scope definition covering endpoint delivery (phishing simulation, assumed breach, or client-side exploitation).
- C2 infrastructure with a valid TLS certificate, domain registered at least 30 days prior, and a categorised hosting provider. Clean malleable profile configured.
- At least one representative target user account or device type in scope.
- Out-of-band communication channel with the client's blue team if running as a purple exercise.

## Passive preparation

Before any payload is built, understand the target environment. Identify the organisation's email security controls (MX records, SPF/DKIM/DMARC configuration), the endpoint management platform (Intune, JAMF, or similar), and the identity provider (Entra ID, Okta, Google Workspace). LinkedIn and job postings reveal the EDR product in most cases.

This preparation determines the delivery mechanism (which email gateway controls are in place), the payload format (macro, HTML smuggling, ISO, or a link-based browser exploit), and the expected post-compromise credential targets (which cloud platforms the compromised user is likely to access).

## Initial access

Deliver the payload through the chosen mechanism. For phishing simulations, this is typically a macro-enabled document, an HTML-smuggled executable, or a credential-harvesting page. For assumed-breach scenarios, the starting point is a low-privilege shell on a domain-joined workstation.

On callback, confirm execution context immediately. Do not proceed until the EDR product is identified and the user's privilege level and domain membership are known.

## EDR evasion and stabilisation

Before any post-exploitation tool is executed, apply AMSI bypass and determine the appropriate injection or execution strategy for the identified EDR product. Migrate into a long-lived legitimate process if the initial execution context is short-lived (a macro process exits when the document is closed).

Establish a stable C2 channel with jitter. The primary channel should be HTTPS to a categorised domain. Set the sleep interval to match the engagement's operational tempo and note that the engagement's detection window starts here.

## Credential harvesting

With a stable session in a legitimate process context, harvest in priority order: Kerberos TGTs, cloud CLI tokens and credential files, browser session cookies for active sessions, and then NTLM hashes. Work quickly; session material ages out.

For each harvested item, confirm validity immediately. A Kerberos TGT can be tested with `Rubeus.exe describe`. Cloud tokens can be validated with a single API call. Browser cookies can be tested with a curl request.

## Cloud and SaaS pivot

Transfer credential material to attacker-controlled infrastructure and establish cloud access independently of the endpoint. From this point the endpoint is not required. Enumerate accessible cloud resources, identify privilege escalation paths within the cloud environment, and document the full set of data and systems accessible to the compromised identity.

Create a durable persistence mechanism in the cloud (new access key, service principal credential, or OAuth token) that does not depend on the endpoint remaining accessible.

## Detection gap assessment

Throughout the chain, note what the EDR and identity controls detected and what they did not. The most valuable finding is the gap between "the endpoint was compromised" and "the cloud access was detected", which in most organisations is measured in hours or days rather than minutes. This gap is the operational window an attacker would use.

Document: the delivery mechanism that succeeded, the EDR techniques that were undetected, the time between initial access and first cloud API call, and whether the identity provider flagged the access from new infrastructure.

## Evidence collection

For each phase capture: the exact technique used, the EDR alert status at the time (if accessible via the blue team), the credential material obtained and its access scope, and a demonstration of the furthest-reaching cloud or SaaS access achieved. The final report should present the full chain as a concrete narrative rather than a list of findings.

## Runbooks

- [Initial access](../runbooks/initial-access.md)
- [EDR bypass](../runbooks/edr-bypass.md)
- [Credential harvesting](../runbooks/credential-harvest.md)
- [Pivot to cloud](../runbooks/pivot-to-cloud.md)
