# Supply chain and vendor assessment

Because your security is only as good as your suppliers'.

The thing about security perimeters is that they're wonderfully effective against people you haven't intentionally 
let inside. Firewalls keep out attackers, network segmentation isolates systems, authentication prevents unauthorised 
access. All of these controls work brilliantly right up until you grant someone vendor access, at which point they can simply walk through all your security controls because they're supposed to be there.

This is rather similar to how the Patrician's Palace is protected by extensive security measures, multiple layers of guards, various deadly traps, and a general atmosphere of "nobody unauthorised gets in". However, the palace also employs numerous servants, tradespeople, and contractors who come and go regularly. Each one of them technically has access to bypass most security measures because they need to do their jobs. The security challenge isn't keeping everyone out, it's distinguishing between legitimate authorised access and malicious authorised access, which is considerably harder.

In OT environments, vendors are everywhere. The PLC vendor needs access to upload firmware updates. The SCADA vendor needs access to troubleshoot software issues. The turbine vendor needs access to monitor equipment performance. The instrumentation vendor needs access to calibrate sensors. Each one needs some level of access to your systems, and each one represents a potential security risk.

At UU P&L, we counted 17 different vendors with some form of technical access to OT systems:

Equipment Vendors (7):
- Turbine manufacturer (permanent VPN access)
- PLC manufacturer (scheduled access for updates)
- SCADA software vendor (remote desktop access)
- Sensor vendor (dial-up modem access, yes really)
- UPS vendor (separate network for monitoring)
- Fire suppression vendor (hardwired connection)
- HVAC controls vendor (cloud-based management)

Service Providers (6):
- Instrument calibration contractor
- Electrical maintenance contractor
- Network equipment supplier
- Backup tape service
- Security system integrator
- General IT support

Utility Providers (4):
- Internet service provider (router management access)
- Cellular carrier (for 4G backup)
- VoIP provider (phone system management)
- Cloud backup provider

Each of these vendors had been granted access through legitimate business need. Each one had presumably been vetted 
by procurement. And each one represented a potential attack vector that bypassed all of UU P&L's network security 
controls.

## Vendor access review

Start by documenting what vendor access exists:

### Create vendor access inventory

For each vendor, document:

1. Vendor Name and Purpose
   - Who are they?
   - What service do they provide?
   - Why do they need access?

2. Access Method
   - VPN? (Always-on or scheduled?)
   - Remote desktop?
   - Physical access to facility?
   - Cloud service?
   - Modem dial-up?

3. Access Scope
   - What systems can they reach?
   - What credentials do they have?
   - What level of access? (Read-only? Admin?)
   - What networks can they access?

4. Access Controls
   - How is access authenticated?
   - Is MFA required?
   - Is access logged?
   - Who reviews access logs?

5. Change Management
   - When was access last reviewed?
   - Who approved access?
   - Is there a contract governing access?
   - When does access expire?

At UU P&L, this inventory revealed several concerning patterns:

Pattern 1: Permanent VPN access: The turbine vendor had a permanent VPN connection that was always up:

```
Vendor: TurbineTech GmbH
Access Method: Site-to-site VPN (always on)
Credentials: Shared PSK (pre-shared key)
Networks Accessible: Engineering VLAN, PLC network
Access Level: Full admin rights
Last Credential Change: 2016 (8 years ago)
Access Review: Never
Monitoring: None
Justification: "Vendor needs to monitor turbine performance"
```

This meant that TurbineTech had permanent, unmonitored admin access to critical control systems. If TurbineTech's network was compromised (which we had no way of knowing), the attacker would have immediate access to UU P&L's control systems.

Pattern 2: Excessive privileges: The SCADA vendor needed occasional access to troubleshoot software issues. They'd been granted:

```
Access: Domain Administrator credentials
Justification: "Sometimes we need to restart services"
Actual need: Local administrator on SCADA servers only
Over-privilege: ~95% (domain admin for entire IT and OT infrastructure)
```

Pattern 3: Undocumented access: A sensor calibration contractor had installed a cellular modem to "check calibration schedules remotely":

```
Access: 4G modem with VPN client
Discovery: Found during wireless survey (not documented)
Credentials: Unknown
Scope: Unknown (connects to unknown external server)
Approval: None (contractor installed without asking)
Duration: 18 months (based on modem purchase date)
```

## Third-party remote access platforms

Many organizations use third-party remote access platforms for vendor management:

### Common platforms

- TeamViewer: Popular but often misconfigured
- AnyDesk: Similar to TeamViewer
- LogMeIn: Enterprise remote access
- BeyondTrust: Privileged access management
- CyberArk: Privileged access management
- Bomgar (now BeyondTrust): Purpose-built for vendor access

At UU P&L, TeamViewer was configured with essentially no security controls:

- No MFA
- No session recording
- No access restrictions
- No logging to SIEM
- Vendor accounts active 24/7
- Shared vendor credentials among multiple technicians
- Last access review: Never

This meant that anyone with the vendor credentials (which were shared among approximately 15 people across three companies) could connect at any time, access any system, and perform any action, with minimal logging and no real-time monitoring.

## Maintenance contract security

Maintenance contracts often include provisions for vendor access, but these are usually written by procurement focusing on service levels, not by security focusing on risk:

### Review maintenance contracts

Security-relevant contract clauses to check:

1. Scope of Access
   ❌ Bad: "Vendor shall have access as necessary to perform services"
   ✓ Good: "Vendor access limited to systems X, Y, Z via method A, during hours B"

2. Credential Management
   ❌ Bad: "Customer shall provide vendor with necessary passwords"
   ✓ Good: "Vendor credentials shall be unique per technician, rotated quarterly, disabled when not in use"

3. Security Requirements
   ❌ Bad: No mention of security
   ✓ Good: "Vendor shall comply with customer security policy, use MFA, maintain patched systems"

4. Liability
   ❌ Bad: "Customer assumes all risk"
   ✓ Good: "Vendor liable for security incidents resulting from vendor access or vendor system compromise"

5. Audit Rights
   ❌ Bad: No mention of auditing
   ✓ Good: "Customer may audit vendor security practices, vendor shall provide evidence of security controls"

6. Termination
   ❌ Bad: "Contract auto-renews annually"
   ✓ Good: "Access privileges expire with contract, vendor must request renewal with justification"

At UU P&L, the turbine maintenance contract (signed in 2016) said:

*"TurbineTech shall be provided with remote access to Customer's turbine control systems as necessary to monitor equipment performance and provide technical support. Customer shall provide appropriate credentials and network access."*

This gave TurbineTech essentially unlimited access with no security requirements, no access restrictions, no liability for security incidents, and no expiration date. The contract had been auto-renewing annually for eight years without any security review.

## Software update mechanisms

How vendors deliver software updates is a critical security concern:

### Assess update delivery methods

Update Delivery Methods (from least to most secure):

1. Vendor downloads update directly to system (via remote access)
   Risk: Vendor has direct system access
   Security: Depends entirely on vendor network security

2. Update sent via email
   Risk: Email compromise, phishing, no integrity verification
   Security: Very weak

3. Update downloaded from vendor website
   Risk: Compromised website serves malicious update
   Security: Weak unless cryptographically signed

4. Update downloaded from vendor website with hash verification
   Risk: Website compromise that also changes hash
   Security: Moderate

5. Update downloaded from vendor website with cryptographic signature
   Risk: Private key compromise (rare)
   Security: Good

6. Update delivered on physical media after approval
   Risk: Supply chain interception (very rare for OT)
   Security: Good (if verification performed)

At UU P&L, update methods varied by vendor:

SCADA vendor: Updates downloaded from vendor website
- Verification: MD5 hash (weak, can be forged)
- Signature: None
- Approval process: IT downloads, engineering installs
- Testing: In production (no test environment)

PLC vendor: Updates uploaded by vendor via remote session
- Verification: None (trust vendor technician)
- Signature: None
- Approval process: Verbal approval over phone
- Testing: In production

Turbine vendor: Updates pushed automatically by vendor
- Verification: Unknown (automatic process)
- Signature: Unknown
- Approval process: None (automatic)
- Testing: In production

The automatic updates from the turbine vendor were particularly concerning. We discovered them during network 
monitoring when we saw firmware upload traffic that nobody had scheduled. Investigation revealed that TurbineTech 
had configured automatic update push, where their system would detect outdated firmware and automatically upload new 
versions, without notifying UU P&L or requesting approval.

This had two implications:

1. TurbineTech could push arbitrary code to production PLCs without authorization
2. If TurbineTech's update server was compromised, malicious updates would be automatically installed

### Software update security assessment

Demonstrate vulnerabilities in vendor update mechanisms:

[🐙 Software Update Security Assessment](https://github.com/ninabarzh/power-and-light/blob/main/topics/update_security_assessment.py)

## Counterfeit component detection

Supply chain attacks can involve counterfeit hardware components:

### Types of counterfeit components

1. Cloned legitimate parts
   - Look identical to authentic parts
   - May function normally
   - May contain backdoors or reduced quality

2. Remarked parts
   - Low-grade parts remarked as high-grade
   - May fail under stress
   - Common in electronic components

3. Recycled parts
   - Removed from discarded equipment
   - Cleaned and sold as new
   - Reduced lifespan, potential contamination

4. Malicious implants
   - Legitimate parts with added malicious hardware
   - Backdoors, data exfiltration, kill switches
   - Very sophisticated, nation-state level

### Detection methods

Visual Inspection:
- Check markings (font, alignment, quality)
- Check packaging (authentic vendors use specific packaging)
- Check documentation (authentic parts include specific docs)
- Compare with known-authentic parts

Electrical Testing:
- Measure physical characteristics (capacitance, resistance)
- Check performance under load
- Compare with datasheet specifications
- Look for abnormal behavior

X-ray Inspection:
- For integrated circuits
- Reveals internal structure
- Can identify added components or modifications
- Expensive but definitive

Supply Chain Verification:
- Purchase only from authorised distributors
- Verify distributor authorization with manufacturer
- Keep chain of custody documentation
- Verify serial numbers with manufacturer

At UU P&L, we didn't find counterfeit components (or at least, none that we detected), but we did find concerning procurement practices:

- Spare PLCs purchased from eBay (authenticity unknown)
- Network switches purchased from grey market supplier (30% cheaper than authorised distributor)
- Replacement SCADA server components purchased from "liquidation sale"

None of these were necessarily counterfeit, but the lack of supply chain verification meant there was no way to be certain. A sophisticated attacker could have introduced compromised hardware at any of these points.

## Vendor security questionnaires

Before granting vendor access, assess their security practices:

### Vendor security questionnaire

Section 1: General Security

1. Do you have a documented information security policy?
2. When was it last reviewed?
3. Who is responsible for security at your organization?
4. Do you have ISO 27001 certification or equivalent?
5. Have you had any security incidents in the past year?
6. Do you have cyber insurance?

Section 2: Access Controls

7. How do you authenticate your technicians' access to customer systems?
8. Do you require MFA for remote access?
9. How often are credentials rotated?
10. Do you use shared credentials or unique credentials per technician?
11. How do you handle credential management when technicians leave?
12. Do you log all access to customer systems?
13. How long are access logs retained?

Section 3: Network Security

14. What is your remote access architecture?
15. Do you use VPN? If so, what technology?
16. Are your remote access systems on a separate network segment?
17. Do you monitor your remote access systems for compromise?
18. Have your remote access systems been penetration tested?
19. What network security controls protect your systems?

Section 4: Endpoint Security

20. What operating systems do technicians use for remote access?
21. Are these systems patched regularly?
22. Do you use endpoint protection (antivirus, EDR)?
23. Are technician systems on a corporate domain or standalone?
24. Do you allow personal devices for customer access?
25. Do you have a BYOD policy?

Section 5: Change Management

26. How do you approve changes to customer systems?
27. Do you maintain backups before changes?
28. How do you test updates before deployment?
29. What is your rollback procedure if updates fail?
30. How do you document changes?

Section 6: Incident Response

31. Do you have an incident response plan?
32. How quickly can you detect a compromise of your systems?
33. What is your notification process if you discover a breach?
34. Do you have a security team or SOC?
35. Have you conducted incident response exercises?

Section 7: Supply Chain

36. How do you verify authenticity of hardware you provide?
37. Do you purchase only from authorised distributors?
38. Do you have supply chain security procedures?
39. How do you verify software authenticity?
40. Do you use code signing for your software?

At UU P&L, we recommended implementing this questionnaire for all vendors with system access. We also recommended 
that contracts should require vendors to:

- Re-certify answers annually
- Notify UU P&L of any security incidents within 24 hours
- Allow UU P&L to audit vendor security practices
- Maintain specific security controls as contract requirements

### The Target-HVAC lesson

The infamous Target breach of 2013 is the canonical example of vendor access gone wrong. Target (the US retailer) 
was breached by attackers who first compromised a HVAC vendor that had remote access to Target's network for energy 
management purposes. From the HVAC vendor's network access, attackers pivoted to Target's payment systems and 
stole 40 million credit card numbers.

The lessons for OT environments:

1. Vendors with seemingly innocuous access can be pivot points
   - HVAC systems seemed low-risk
   - But network access is network access
   - Attackers used it to reach payment systems

2. Vendor security is your security
   - Target's security was excellent
   - HVAC vendor's security was not
   - Attackers chose the easier target

3. Network segmentation matters
   - If HVAC network was truly isolated, breach wouldn't have reached payment systems
   - Network segmentation was insufficient

4. Monitoring vendor activity matters
   - If unusual activity from HVAC vendor had been detected, breach could have been stopped
   - Vendor activity wasn't adequately monitored

At UU P&L, the parallels were concerning. The turbine vendor had permanent network access, just like Target's HVAC vendor. The segmentation between the turbine vendor's access and critical systems was weak, just like at Target. Monitoring of vendor activity was minimal, just like at Target.

We could describe UU P&L's vendor access architecture as "Target-HVAC-style attack waiting to happen", but that seemed a bit blunt for a professional report. We said instead: "The vendor access architecture presents similar risks to those exploited in well-documented retail sector breaches involving HVAC contractors, and should be redesigned with similar mitigations."

They got the message.

### Vendor access recommendations

Based on assessment findings, we provided recommendations:

Immediate (implement within 30 days)

1. Inventory all vendor access: Document every vendor with system access
2. Disable unused access: Accounts not used in 90 days should be disabled
3. Enable MFA: All vendor remote access must use multi-factor authentication
4. Rotate credentials: Change all vendor credentials, establish 90-day rotation
5. Enable logging: Forward all vendor access logs to SIEM

Short-term (implement within 90 days)

6. Implement jump hosts: Vendors connect to jump host, not directly to systems
7. Session recording: Record all vendor sessions for audit
8. Time-based access: Vendor access only enabled during scheduled maintenance windows
9. Privileged access management: Deploy PAM solution for vendor credential management
10. Contract review: Update maintenance contracts with security requirements

Long-term (implement within 6 months)

11. Network segmentation: Isolate vendor access to dedicated VLAN with strict filtering
12. Vendor security audits: Annual security assessment of high-risk vendors
13. Update verification: All vendor updates must be cryptographically signed
14. Supply chain security: Procurement policy requiring authorised distributors only
15. Continuous monitoring: Deploy tools to detect anomalous vendor activity

At UU P&L, implementing these recommendations reduced vendor-related risk significantly:

- Vendor accounts reduced from 47 to 12 (35 were orphaned accounts from former vendors)
- Permanent VPN access eliminated (replaced with scheduled just-in-time access)
- All vendor access now logged and monitored
- Automatic firmware updates disabled (replaced with approved change management)
- Vendor credentials now managed through PAM system (unique per technician, automatically rotated)

The turbine vendor initially objected to the changes, arguing that the new requirements would slow down emergency response. UU P&L's response was essentially: "Your permanent, unmonitored admin access is a greater risk than slightly slower emergency response, and you can have scheduled access or no access, your choice."

The vendor chose scheduled access.

The fundamental insight about supply chain and vendor security is that you cannot outsource risk. When you grant vendors access to your systems, their security becomes your security. Their password management becomes your password management. Their network protection becomes your network protection. A breach of their systems can become a breach of your systems.

This doesn't mean you shouldn't use vendors (you must, nobody can do everything in-house), but it does mean that vendor management is security management. Every vendor with system access should be viewed as an extension of your security perimeter, with appropriate controls, monitoring, and accountability. Otherwise, you're spending millions on firewalls and intrusion detection while leaving the back door unlocked with a sign saying "VENDORS ENTER HERE".
