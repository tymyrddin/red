# Supply chain and vendor security: Because your security is only as good as your suppliers

*Or: Why Ponder Worried About The Doors You Deliberately Leave Open*

## The problem with authorised access

The thing about security perimeters is that they're wonderfully effective against people you haven't intentionally let inside. Firewalls keep out attackers, network segmentation isolates systems, authentication prevents unauthorised access. All of these controls work brilliantly right up until you grant someone vendor access, at which point they can simply walk through all your security controls because they're supposed to be there.

This is rather similar to how the Patrician's Palace is protected by extensive security measures, multiple layers of guards, various deadly traps, and a general atmosphere of "nobody unauthorised gets in". However, the palace also employs numerous servants, tradespeople, and contractors who come and go regularly. Each one of them technically has access to bypass most security measures because they need to do their jobs. The security challenge isn't keeping everyone out. It's distinguishing between legitimate authorised access and malicious authorised access, which is considerably harder.

In OT environments, vendors are everywhere. The PLC vendor needs access to upload firmware updates. The SCADA vendor needs access to troubleshoot software issues. The turbine vendor needs access to monitor equipment performance. The instrumentation vendor needs access to calibrate sensors. Each one needs some level of access to your systems, and each one represents a potential security risk.

At actual facilities (the sort Ponder encountered during consulting work), vendor counts typically ranged from 12 to 25 different organisations with some form of technical access to OT systems. Equipment vendors, service providers, utility companies, each with permanent VPN connections, remote desktop access, or physical access to facilities. Each vendor had been granted access through legitimate business need. And each one represented a potential attack vector that bypassed all network security controls.

## What the simulator doesn't include (yet)

The UU P&L simulator currently focuses on industrial protocol vulnerabilities. It doesn't simulate:

Not in current simulator:
- Vendor remote access (VPNs, remote desktop)
- Third-party support platforms (TeamViewer, AnyDesk)
- Software update mechanisms
- Supply chain component verification
- Vendor credential management
- Remote support scenarios

Current simulator scope:
- Direct protocol access to PLCs and SCADA
- Unauthenticated communication channels
- Protocol-level vulnerabilities
- Device reconnaissance and exploitation

This simplification allows focus on protocol security, but it misses an entire class of real-world attack vectors.

## Why supply chain security matters in OT

Supply chain and vendor access represent critical security concerns in operational technology:

### The Target-HVAC lesson

The infamous Target breach of 2013 is the canonical example of vendor access exploitation. Target (the US retailer) was breached by attackers who first compromised an HVAC vendor that had remote access to Target's network for energy management purposes. From the HVAC vendor's network access, attackers pivoted to Target's payment systems and stole 40 million credit card numbers.

The lessons for OT environments:

1. Vendors with seemingly innocuous access can be pivot points
2. Vendor security is your security
3. Network segmentation must include vendor access
4. Monitoring vendor activity is essential

In OT, vendor access is typically more extensive than in IT:
- Direct PLC programming access
- SCADA system administrator rights
- Safety system configuration access
- Physical access to control rooms

If a vendor is compromised, attackers inherit all these privileges.

### NotPetya and software updates

The NotPetya attack in 2017 compromised Ukrainian accounting software (MEDoc), used the update mechanism to distribute malware to all customers, and caused approximately $10 billion in global damage. Several affected companies had OT systems impacted when the malware spread from IT to OT networks.

The lessons:
- Software updates are attack vectors
- Compromised vendors can push malicious updates
- Update verification mechanisms often don't exist
- OT environments may not detect malicious updates until physical impact occurs

### Stuxnet and supply chain insertion

Stuxnet (2010) demonstrated supply chain compromise at the component level, potentially inserting malicious code during manufacturing or distribution of industrial control system components.

The lessons:
- Hardware supply chain can be compromised
- Counterfeit or modified components may contain backdoors
- Detection of hardware-level compromises is extremely difficult
- Nation-state attackers use sophisticated supply chain attacks

## What could be added to the simulator

Future simulator enhancements could include supply chain and vendor security scenarios:

### Vendor remote access simulation

Simulated vendor VPN:
- Permanent VPN connection representing vendor access
- Default or weak credentials (admin/admin)
- Excessive privileges (access to all systems)
- Scripts to demonstrate lateral movement from vendor network
- Tools showing privilege escalation via vendor access

Educational scenarios:
- Vendor account compromise leading to facility compromise
- Excessive vendor privileges enabling wide-scale access
- Unmonitored vendor activity going undetected
- Vendor credential theft and misuse

Why this would be valuable:
- Demonstrates real-world attack vector
- Shows why vendor access governance matters
- Teaches vendor risk assessment
- Illustrates supply chain security failures

### Third-party remote access platforms

Simulated TeamViewer/remote desktop:
- Remote support software with weak configuration
- Shared vendor credentials
- Unlogged access sessions
- Scripts to demonstrate unauthorised access via stolen vendor credentials

Educational scenarios:
- Remote support credential theft
- Unauthorised access via legitimate remote support tools
- Session hijacking
- Persistence via remote access tools

Why this would be valuable:
- Common in real OT environments
- Frequently misconfigured
- Demonstrates practical attack scenarios
- Teaches remote access security assessment

### Software update mechanism simulation

Simulated update server:
- Vendor update server for PLC firmware
- Unsigned or weakly signed updates
- Insecure update delivery (HTTP, no verification)
- Scripts to demonstrate update manipulation
- Tools showing malicious update injection

Educational scenarios:
- Man-in-the-middle update interception
- Malicious update injection
- Update server compromise
- Unsigned update acceptance

Why this would be valuable:
- Shows critical supply chain vulnerability
- Demonstrates why update verification matters
- Teaches secure update assessment
- Illustrates software supply chain attacks

### Vendor credential management

Simulated privileged access management (PAM):
- Scenarios with shared vendor credentials
- Scripts showing credential theft from jump hosts
- Tools demonstrating credential reuse
- Comparison with proper PAM implementation

Educational scenarios:
- Shared vendor password discovery
- Credential file extraction from engineering workstations
- Long-lived vendor credentials exploitation
- Proper credential rotation demonstration

Why this would be valuable:
- Shows common vendor credential weaknesses
- Demonstrates proper credential management
- Teaches vendor access control assessment
- Illustrates privileged access management benefits

### Supply chain component verification

Simulated counterfeit component scenarios:
- Scripts to verify component authenticity
- Tools to demonstrate supply chain verification
- Educational content on counterfeit detection
- Guidance on secure procurement practises

Why this would be valuable:
- Raises awareness of hardware supply chain risks
- Demonstrates verification techniques
- Teaches procurement security assessment
- Illustrates physical supply chain security

## The relationship to protocol vulnerabilities

Vendor and supply chain security connects to protocol security in several ways:

### Vendors provide the initial access

Attack progression:

1. Compromise vendor network or steal vendor credentials
   - Phishing vendor employees
   - Exploiting vendor systems
   - Social engineering vendor support staff

2. Use vendor's legitimate access to reach customer OT network
   - Connect via vendor VPN
   - Use vendor remote desktop access
   - Leverage vendor's privileged credentials

3. Conduct reconnaissance using industrial protocols
   - Port scanning for PLCs and SCADA
   - Protocol fingerprinting
   - This is what simulator currently teaches

4. Exploit protocol-level vulnerabilities
   - Unauthenticated Modbus access
   - Anonymous OPC UA browsing
   - S7 memory reading
   - This is what simulator currently demonstrates

The simulator currently focuses on steps 3-4. Adding vendor access scenarios would complete the attack chain, showing steps 1-2.

### Vendors deliver the malicious payload

Alternative attack progression:

1. Compromise vendor update infrastructure
2. Inject malicious code into legitimate update
3. Vendor pushes update to customer systems
4. Malicious code executes with system privileges
5. Attacker gains direct access to OT systems

This bypasses all perimeter security because the malicious code arrives via trusted vendor update mechanism.

## Ponder's perspective

Ponder's testing journal included notes about supply chain security:

"The simulator demonstrates what happens when attackers have network access to industrial protocols. It doesn't demonstrate how they obtain that access in the first place.

"In actual facilities, vendor access is a common initial foothold. Permanent VPN connections with default credentials. Remote desktop access with shared passwords. Update mechanisms with no signature verification. Each one is a door you've deliberately left open, and whilst you trust the vendor, attackers target the vendor precisely because you trust them.

"The Target breach demonstrated this perfectly. Nobody attacked Target's payment network directly. They attacked the HVAC vendor who had network access. The vendor was the easier target, and vendor access was the bridge to the real objective.

"The simulator could be enhanced to include vendor access scenarios. Simulated VPNs with weak credentials. Simulated remote support sessions with insufficient logging. Simulated update mechanisms with no verification.

"This would teach a critical lesson: your security depends on your vendors' security. If vendors are compromised, their access becomes the attacker's access. Protocol-level security doesn't help if attackers arrive via trusted vendor channels.

"Supply chain security isn't about industrial protocols. It's about trust, governance, and the uncomfortable reality that you cannot outsource risk even when you must outsource work."

## What could be taught with enhanced simulation

Adding supply chain scenarios to the simulator would provide educational value:

### For security professionals

Assessment techniques:
- How to inventory vendor access
- How to assess vendor security practises
- How to identify excessive vendor privileges
- How to test vendor access controls

Attack scenarios:
- Vendor credential theft leading to customer compromise
- Vendor network compromise enabling customer access
- Malicious update injection
- Supply chain backdoor insertion

### For operators and engineers

Operational security:
- Why vendor access needs governance
- How to detect unauthorised vendor activity
- When to grant and revoke vendor access
- What secure vendor access looks like

Risk awareness:
- How vendor compromise affects facility security
- Why shared credentials are dangerous
- Why permanent access is risky
- How to balance operational needs with security

### For management

Strategic understanding:
- Cost-benefit of vendor access governance
- Risk of vendor compromise
- Contract security requirements
- Supply chain risk management

Decision support:
- When to trust vendors
- When to require security audits
- How to structure vendor access
- What controls justify the cost

## Future development priorities

If supply chain and vendor scenarios were added to the simulator:

### Priority 1: Vendor VPN access scenario
- Educational value: Very high (common attack vector)
- Technical complexity: Moderate
- Integration: Excellent (provides initial access for protocol attacks)
- Real-world relevance: Very high

Implementation:
- Simulated VPN endpoint with weak credentials
- Scripts to discover and exploit vendor access
- Tools to demonstrate lateral movement from vendor network
- Comparison with properly configured vendor access

### Priority 2: Software update manipulation
- Educational value: High (critical supply chain risk)
- Technical complexity: Moderate
- Integration: Good (demonstrates why update security matters)
- Real-world relevance: High

Implementation:
- Simulated PLC update server
- Scripts to intercept and modify updates
- Tools to demonstrate unsigned update injection
- Comparison with cryptographically signed updates

### Priority 3: Third-party remote access platforms
- Educational value: High (extremely common in practice)
- Technical complexity: Low
- Integration: Good (provides alternative access path)
- Real-world relevance: Very high

Implementation:
- Simulated TeamViewer/remote desktop scenario
- Scripts to demonstrate credential theft
- Tools showing session hijacking
- Best practises for remote access management

### Priority 4: Vendor security assessment framework
- Educational value: Moderate (process-oriented)
- Technical complexity: Low (mostly documentation)
- Integration: Fair (complements technical scenarios)
- Real-world relevance: High

Implementation:
- Vendor security questionnaire templates
- Assessment checklists
- Contract review guidance
- Vendor risk scoring methodology

## Current state and future potential

The simulator currently teaches protocol-level security assuming network access exists. This is valuable and focused, but incomplete.

Real-world OT security must address:
- How attackers obtain network access (often via vendors)
- How to assess vendor security
- How to govern vendor access
- How to verify supply chain integrity

These are largely process and policy concerns rather than technical vulnerabilities, but they have technical components (credential management, VPN configuration, update verification) that could be simulated.

Future enhancements would create a more comprehensive OT security education platform, teaching both technical protocol security and organisational vendor risk management.

## The uncomfortable truth about vendor access

The fundamental problem with vendor access is that you cannot eliminate it. You need vendors. Nobody can do everything in-house. Equipment vendors understand their systems better than you do. Software vendors can troubleshoot problems you can't solve. Service providers perform functions you lack capacity for.

But needing vendors doesn't mean trusting them blindly. It means:
- Governing vendor access (scheduled, not permanent)
- Monitoring vendor activity (log everything)
- Limiting vendor privileges (least privilege principle)
- Verifying vendor security (questionnaires, audits)
- Contractual accountability (liability for vendor breaches)

The simulator could teach what this looks like in practice, demonstrating both weak vendor access (permanent VPN with default credentials) and strong vendor access (scheduled just-in-time access with MFA and session recording).

## Conclusion

The UU P&L simulator currently focuses on industrial protocol security, which is its strength. Supply chain and vendor security are outside current scope but represent critical real-world attack vectors.

Future enhancements could include vendor access scenarios, demonstrating how attackers leverage trusted vendor relationships to compromise facilities. This would complete the picture of OT security, showing not just how protocols are vulnerable, but how attackers gain the access needed to exploit those protocols.

Until then, supply chain security should be understood as complementary to protocol security. Both matter. Both require assessment. The simulator teaches one, standard vendor risk management frameworks teach the other, and comprehensive OT security requires both.

Your firewall is only as strong as the vendor VPN that bypasses it.

---

Further reading:
- [Remote Access Security](remote.md) - Wireless and remote access vulnerabilities
- [Workstation Security](../vulnerabilities/workstation.md) - Engineering access as vendor pivot point
- [Network Security](../vulnerabilities/network.md) - Network segmentation and vendor isolation

For vendor risk management frameworks and supply chain security, consult standard IT security resources and IEC 62443 guidance. The simulator focuses on technical protocol security, assuming access exists through vendor or other channels.
