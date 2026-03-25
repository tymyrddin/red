# Endpoint surface discovery

Understanding the endpoint landscape before an engagement informs every subsequent decision: what EDR is running, how devices authenticate, which cloud services they reach, and where the identity infrastructure sits. Most of this can be learned passively.

## Asset and configuration enumeration

Organisations expose their endpoint management configuration in ways that are rarely considered sensitive. Job postings describe the MDM platform, EDR vendor, and operating system mix. LinkedIn profiles of IT staff name the tools they manage. Support documentation published externally sometimes describes agent rollout procedures, naming conventions, and domain join processes.

Certificate transparency logs and DNS records reveal mobile device management endpoints, email autodiscover configurations, and identity provider URLs. An Entra ID or Okta tenant is often identifiable from a simple DNS lookup against the organisation's primary domain.

Active Directory, where it exists, is the most information-dense source available to any authenticated domain user. LDAP queries return all computer objects including their operating system version, last logon time, and the accounts that have interactively logged on. BloodHound collection from any domain credential maps the full identity graph including which users log on to which machines and which machines hold sessions for privileged accounts.

## EDR and security tool fingerprinting

Identifying which EDR product is deployed before delivering any payload avoids the most common detection failures. Several passive indicators help:

Driver names and service names associated with commercial EDR products are consistent across deployments. From an already-compromised endpoint, `sc query type= driver` and `tasklist /svc` enumerate running security software. The presence of specific named pipes (visible with tools like Process Hacker) identifies CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, and others.

From an external position, certificate metadata on the organisation's domain controllers and management servers sometimes reveals the security platform. Shodan results for the organisation's IP range may show management console banners.

## Remote access inventory

Remote access infrastructure is the soft edge of the endpoint perimeter. VPN concentrators, Citrix gateways, RDP brokers, and Zscaler Private Access deployments are all visible externally. Each represents an authentication endpoint where credential attacks are possible.

BYOD environments complicate this further: personal devices connecting to corporate resources are subject to whatever hygiene the employee applies, which may be considerably less than the corporate standard. MDM enrolment status, OS patch level, and local firewall configuration are all inconsistent across a BYOD fleet, and the management plane often cannot enforce controls on devices it does not own.

## The enumeration target

The information gathered here answers three questions that drive the rest of the engagement: what detects execution on the endpoint, what credentials and tokens does the endpoint hold, and what can those credentials reach. The answers determine which delivery mechanism, which evasion approach, and which post-compromise pivot path to prioritise.
