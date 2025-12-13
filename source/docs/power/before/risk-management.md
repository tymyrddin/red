# Risk management

Risk management in IT security is relatively straightforward. You calculate risk as Impact × Likelihood, prioritise 
accordingly, and accept that some spreadsheets might get encrypted or some customer data might leak.

Risk management in OT security requires a different mindset. When "impact" can include "steam explosion", 
"toxic release", "equipment destruction costing millions", or "angry Librarian", the calculations become rather 
more serious.

The goal isn't to eliminate all risk. That's impossible. The goal is to understand the risks, make informed decisions 
about which risks are acceptable, and ensure that the people making those decisions understand what they're accepting.

## Risk equals impact times likelihood, when impact includes explosions

The traditional risk formula is simple:

```text
Risk = Impact × Likelihood
```

For a web application, this might be:
- Impact: Loss of customer data (financial cost, reputational damage, regulatory fines)
- Likelihood: Medium (some vulnerabilities exist, attackers are motivated)
- Risk: Medium to High

For an industrial control system at UU P&L, this becomes:

### Example: Reactor control system compromise

Impact:
- Safety: Potential loss of containment, alchemical incident, injuries or fatalities, campus evacuation
- Financial: €60 million+ for cleanup, equipment replacement, compensation, fines
- Environmental: Magical contamination requiring extensive remediation
- Reputational: Loss of operating licence, criminal investigation, Patrician displeasure
- Operational: Months to years to rebuild and restore operations

Likelihood:
- Vulnerabilities exist (no authentication on PLC, engineering workstation bridging networks, weak security throughout)
- Motivated attackers exist (nation states, extremist groups, possibly disgruntled former staff)
- However, requires specific knowledge of reactor systems
- And requires intent to cause harm (most attackers want money or disruption, not mass casualties)

Assessment: Medium likelihood

Overall risk: Unacceptably high

Even medium likelihood of catastrophic impact equals unacceptable risk. This drives security investment decisions. You spend money to reduce likelihood (better security controls) or impact (better safety systems, redundancy, containment).

### Example: Building HVAC compromise

Impact:
- Safety: Discomfort, possible health issues if temperatures extreme for extended periods
- Financial: Energy waste, equipment damage if poorly controlled
- Reputational: Minor embarrassment
- Operational: Degraded working conditions but operations continue

Likelihood:
- Vulnerabilities exist (BACnet with no authentication, accessible from corporate network)
- Attackers less motivated (low value target)
- Assessment: Low to medium likelihood

Overall risk: Low to medium, acceptable with monitoring

The HVAC risk doesn't warrant the same investment as the reactor. You implement basic controls (network segmentation, monitoring) but accept remaining risk.

### The exception: The Library climate control

This requires special consideration. Technically, it's just HVAC. But the consequences of failure include:

Impact if Library temperature rises above 19°C:
- Books deteriorate
- Magical tomes become unstable
- L-space integrity weakens
- The Librarian becomes progressively more irritable
- Above 21°C, the Librarian becomes actively hostile

The financial impact is calculable (rare book collection valued at €240 million+). The safety impact is harder to quantify (what's the monetary value of not being transformed into a bookend by an angry orangutan?).

Risk assessment: Medium likelihood, catastrophic impact (from certain perspectives), overall high risk

Security investment in Library climate control is therefore disproportionate to its apparent importance as "just HVAC". This is OT security in a nutshell: context matters enormously.

## Determining what's testable vs what's demonstrable

In IT security testing, if you find a vulnerability, you exploit it (in controlled manner) to demonstrate impact. You show the SQL injection working, the authentication bypass succeeding, the privilege escalation occurring.

In OT security testing, many vulnerabilities cannot be safely exploited in production. You must determine what you can test directly and what you can only demonstrate theoretically.

### Testable: Things you can do without physical consequences

Reading operations:
- Query PLC for configuration and current values
- Download PLC programs
- Read sensor data via industrial protocols
- Enumerate devices on networks
- Access HMI screens and data
- Query SCADA databases
- Retrieve historian data

These operations don't change physical state. At worst, excessive polling might impact performance, but done carefully they're safe.

Authentication and access control testing:
- Attempt to access systems with various credentials
- Test default passwords
- Verify access control enforcement
- Check for authentication bypass
- Test session management

As long as you're only testing access without making changes, these are generally safe.

Network security testing:
- VLAN segmentation verification
- Firewall rule testing
- Network path discovery
- Protocol analysis
- Traffic monitoring

Network testing can be done safely with proper care about scan speeds and packet rates.

### Demonstrable: Things you can prove but shouldn't do

Write operations to production systems:
- Uploading modified PLC logic
- Changing setpoints or configurations
- Sending control commands to actuators
- Modifying SCADA databases
- Altering alarm limits

You can demonstrate these are possible by:
- Testing on duplicate systems in lab
- Showing the protocol commands that would work
- Demonstrating capability on simulators
- Documenting lack of controls preventing these actions
- Creating video proof-of-concept in test environment

Denial of service attacks:
- Crashing PLCs with malformed packets
- Flooding networks with traffic
- Exhausting system resources
- Forcing repeated safety shutdowns

You demonstrate these by:
- Testing on isolated equipment
- Creating theoretical analysis
- Referencing known vulnerabilities affecting similar systems
- Documenting lack of protections

Safety system interference:
- Disabling interlocks
- Bypassing safety logic
- Preventing safety shutdowns

You demonstrate these by:
- Architecture analysis showing lack of isolation
- Documentation review showing theoretical access paths
- Never, under any circumstances, actually testing on live safety systems

### The testing protocol at UU P&L

For the turbine control systems, the testing plan specified:

May test:
- Network reconnaissance and mapping
- PLC enumeration and identification
- Reading configuration and current state
- Downloading PLC programs to analyse offline
- Testing authentication on HMIs and engineering workstations
- Web application testing on SCADA interfaces
- Credential testing with provided test accounts

May demonstrate but not execute:
- Uploading modified PLC logic (demonstrated on spare PLC in lab)
- Changing turbine setpoints (demonstrated on simulator)
- Operating valves or actuators (shown theoretically via protocol analysis)
- Causing denial of service (theoretical, based on known vulnerabilities)

Absolutely forbidden:
- Any interaction with safety PLCs beyond observation
- Any write operations to production PLCs
- Any commands that affect physical equipment state
- Any testing during peak demand periods
- Any testing without explicit approval for that specific test

This separation ensures you can demonstrate vulnerabilities and their impact without actually causing the disasters you're trying to prevent.

## Risk acceptance by business owners

Finding vulnerabilities is only part of the job. Getting business owners to accept responsibility for addressing them (or consciously accepting the risk of not addressing them) is equally important.

### The risk acceptance conversation

After testing, you present findings to stakeholders. For each significant vulnerability, you need:

1. Clear description of the vulnerability: What's wrong, in terms they understand
2. Realistic impact assessment: What could actually happen if exploited
3. Likelihood assessment: How probable is exploitation
4. Mitigation options: What can be done about it, with costs and trade-offs
5. Risk acceptance: A conscious decision to fix it, mitigate it, or accept the risk

The challenge is getting meaningful risk acceptance. Not a checkbox exercise, but genuine understanding and decision-making.

### Example: The turbine PLC authentication issue

Vulnerability: Turbine PLCs have no authentication. Anyone on the control network can upload programs, change configurations, or send commands.

Impact: An attacker with network access could:
- Modify control logic causing turbine damage (€18M per turbine)
- Trip turbines causing city-wide outage (financial and reputational impact)
- Disable safety limits creating dangerous conditions

Likelihood: Medium. Requires network access to control network. Multiple pathways exist (compromised engineering workstation, contractor access, that wireless access point). Motivated attackers exist. Required knowledge is available.

Overall risk: High. Medium likelihood × Very high impact = High risk.

Mitigation options:

Option 1: Replace PLCs with modern models supporting authentication
- Cost: €600,000+ for PLCs, engineering, testing, commissioning
- Timeline: 18-24 months
- Risk reduction: High (eliminates authentication vulnerability)
- Operational impact: Requires extended outage for replacement

Option 2: Network segmentation and authentication at network layer
- Cost: €120,000 for firewalls, configuration, integration
- Timeline: 6 months
- Risk reduction: Medium (prevents unauthorised network access to PLCs)
- Operational impact: Minimal if done carefully

Option 3: Enhanced monitoring and intrusion detection
- Cost: €60,000 for IDS and monitoring infrastructure
- Timeline: 3 months
- Risk reduction: Low to medium (detects attacks but doesn't prevent them)
- Operational impact: Minimal

Option 4: Accept risk
- Cost: €0 immediately (but unlimited if incident occurs)
- Timeline: Immediate
- Risk reduction: None
- Operational impact: None until incident occurs

The conversation with the Archchancellor (business owner):

"Archchancellor, the turbine PLCs can be reprogrammed by anyone who can access the control network. This means an attacker could cause turbine damage or city-wide outages."

"How likely is this to actually happen?"

"Medium likelihood. We found several ways attackers could access that network. Nation states, ransomware gangs, or even contractors could potentially exploit this."

"What's it cost to fix?"

"Complete fix requires replacing PLCs, that's €600,000 and two years. Partial fix with network controls is €120,000 and six months. Monitoring only is €60,000 and three months."

"What if we do nothing?"

"If an incident occurs, we're looking at €18 million for turbine replacement, plus outage costs, plus regulatory penalties, plus the Patrician's extreme displeasure. Also, our insurance may not cover damage resulting from known, unmitigated cyber vulnerabilities."

"I see. What do you recommend?"

"Network segmentation as minimum acceptable control. It doesn't eliminate the PLC vulnerability but makes it much harder to exploit. Consider PLC replacement in the next capital equipment cycle."

"Very well. Implement the network segmentation. Add PLC replacement to the five-year plan."

This is documented as risk acceptance: Leadership acknowledges the vulnerability, understands the risk, has chosen to implement partial mitigation and accept residual risk. If an incident occurs, this decision is documented.

### What risk acceptance is not

Risk acceptance is not:
- Ignoring findings because they're inconvenient
- Saying "we'll think about it" and never deciding
- Claiming ignorance ("we didn't know it was important")
- Deferring indefinitely ("we'll address it next year")
- Assuming someone else will handle it

True risk acceptance requires:
- Understanding the risk
- Evaluating mitigation options
- Making a conscious decision
- Documenting that decision
- Taking responsibility for consequences

At UU P&L, proper risk acceptance means the Archchancellor signs off on accepting specific risks. If something goes wrong later, there's documentation showing the risk was known and a decision was made. This protects the security team ("we told them") and clarifies leadership accountability.

## Insurance implications

Cyber insurance for industrial facilities has become increasingly important and increasingly complex. Insurers want to know about cyber risks before underwriting policies.

### What insurers care about

Insurance companies evaluating UU P&L ask:
- What cyber security controls are in place?
- Have you conducted security assessments?
- What vulnerabilities are known and unmitigated?
- What's your incident response capability?
- Have you had previous incidents?
- What's the potential maximum loss?

They particularly care about:
- Known vulnerabilities that aren't being addressed
- Lack of basic security hygiene (patching, access controls, monitoring)
- No incident response plan
- No backup and recovery capabilities
- Previous incidents with poor response

### The vulnerability disclosure problem

If pentesting reveals significant vulnerabilities, you face a dilemma:

Disclose to insurer:
- Pros: Maintains honesty with insurer, avoids claim denial later
- Cons: May increase premiums or reduce coverage

Don't disclose:
- Pros: Maintains current coverage and premiums
- Cons: Insurer may deny claims related to known vulnerabilities, potential fraud issues

The ethical and legal answer is disclose. But pragmatically, this requires a remediation plan.

Insurance-friendly approach at UU P&L

1. Conduct security assessment
2. Identify vulnerabilities and risks
3. Develop remediation roadmap with timeline
4. Implement quick wins immediately
5. Disclose findings to insurer with remediation plan
6. Update insurer as remediation progresses

This shows due diligence. You're not hiding vulnerabilities, you're actively addressing them. Insurers generally respond better to "we found problems and are fixing them" than "we have no idea what our security posture is".

### Policy exclusions to watch for

Many cyber insurance policies exclude:
- Damage from nation state attacks (sometimes)
- Damage from known but unmitigated vulnerabilities
- Physical damage from cyber incidents (some policies)
- Business interruption beyond certain limits
- Damage from insider threats (sometimes)

Understanding exclusions is critical. If your reactor controls are vulnerable and you know it, and someone exploits that to cause physical damage, your insurance may not cover it.

At UU P&L, the insurance policy specifically excludes:
- Acts of war and nation state attacks
- Damage resulting from known vulnerabilities unaddressed for more than 180 days
- Physical damage exceeding €60 million
- Certain high-risk experiments in the alchemical reactor (this predates cyber concerns)

This shapes risk management. Vulnerabilities must be addressed within 180 days or risk acceptance must explicitly acknowledge potential insurance exclusion.

## Regulatory requirements

OT security isn't just good practice, it's increasingly legally mandated. Multiple regulatory frameworks apply to UU P&L and similar organisations.

### EU NIS2 Directive

The Network and Information Security Directive 2 (NIS2) applies to critical infrastructure across the EU, including energy providers. UU P&L, providing electricity to Ankh-Morpork, falls under these requirements.

NIS2 requires:
- Risk management measures appropriate to the level of risk
- Business continuity and crisis management
- Supply chain security
- Security in network and information system acquisition, development, and maintenance
- Policies and procedures for assessing effectiveness of security measures
- Cybersecurity training
- Use of cryptography and encryption
- Human resources security, access control, and asset management
- Multi-factor authentication or continuous authentication solutions
- Secured voice, video, and text communications
- Secured emergency communication systems

Penalties for non-compliance:
- Up to €10 million or 2% of annual global turnover (whichever is higher) for essential entities
- Management can be held personally liable

For UU P&L, this means:
- Security assessments aren't optional, they're legally required
- Identified risks must be addressed or formally accepted with documentation
- Board-level responsibility for security
- Regular reporting to regulators

### IEC 62443

The IEC 62443 series provides standards for industrial automation and control systems security. It's not legally mandated in most jurisdictions but is increasingly referenced in contracts and regulations.

IEC 62443 defines:
- Security levels (SL 1-4) based on threat sophistication
- Technical security requirements for systems and components
- Security practices for system lifecycle
- Product development security requirements

For UU P&L, adopting IEC 62443 means:
- Assessing required security levels for each system (turbine controls might be SL 2-3, safety systems might be SL 3-4)
- Implementing technical controls appropriate to security level
- Following secure development practices for any custom software
- Requiring vendors to provide products meeting appropriate security levels

This isn't a quick checkbox exercise. Full IEC 62443 compliance can take years and significant investment.

### UK CNI regulations

As critical national infrastructure (electricity provider for a major city), UU P&L falls under UK CNI protection requirements. This includes:
- Regular security assessments
- Reporting significant incidents
- Coordination with national cyber security centre
- Meeting baseline security requirements

### GDPR considerations

Surprisingly, GDPR applies even in OT environments. Personnel data (employee records, access logs, video surveillance) is personal data requiring protection. If a breach exposes this data, GDPR penalties apply.

At UU P&L:
- HR system with employee data
- Access control systems with logs of who entered where
- Video surveillance in control rooms and substations
- Engineering workstations with personal files and emails

All require GDPR-compliant protection. A ransomware incident encrypting or exfiltrating this data triggers GDPR breach notification requirements within 72 hours.

### The compliance burden

Meeting all these requirements requires:
- Regular security assessments (at least annually)
- Documented risk management process
- Incident response capability
- Regular training
- Vendor security requirements
- Audit trails and logging
- Reporting to regulators

For UU P&L, this means security isn't discretionary. The Archchancellor can't simply decide security is too expensive. Regulatory compliance mandates minimum security standards.

This actually helps security teams. "We need to do this for compliance" is often more compelling than "we need to do this for security". Leadership understands regulatory penalties in ways they sometimes don't understand cyber risk.

## Building a risk register

A risk register is a structured way to track identified risks, their assessment, mitigation status, and ownership. It's a living document that evolves as you identify new risks and address existing ones.

### Risk register structure at UU P&L

Each risk entry includes:

Risk ID: Unique identifier (e.g., RISK-OT-001)

System/Asset: What's affected (Turbine Control PLCs, SCADA Server, etc.)

Vulnerability: What's wrong (No authentication, Unpatched OS, etc.)

Threat: Who might exploit it (Nation state, Ransomware gang, Insider, etc.)

Impact: Consequences if exploited (categorised: Safety, Financial, Environmental, Reputational, Operational)

Likelihood: How probable is exploitation (Low, Medium, High, Critical)

Risk Level: Calculated from Impact × Likelihood (Low, Medium, High, Critical)

Current Controls: Existing mitigations in place

Residual Risk: Risk level after current controls

Mitigation Plan: What will be done to address it

Owner: Who's responsible for mitigation

Status: Open, In Progress, Mitigated, Accepted

Target Date: When mitigation should be complete

Review Date: When risk will be reassessed

### Example entries from UU P&L risk register:

RISK-OT-001
- System: Turbine Control PLCs
- Vulnerability: No authentication on S7 protocol
- Threat: Nation state, Ransomware gang, Contractor
- Impact: Very High (€18M+ equipment damage, city-wide outage)
- Likelihood: Medium (network access possible via multiple paths)
- Risk Level: Critical
- Current Controls: Physical security, limited network access
- Residual Risk: High
- Mitigation: Implement network segmentation with authentication at network layer
- Owner: OT Engineering Manager
- Status: In Progress
- Target Date: Q2 2026
- Review Date: Quarterly

RISK-OT-015
- System: Library Climate Control
- Vulnerability: BACnet protocol with no authentication
- Threat: Disgruntled staff, External attacker via corporate network
- Impact: High (€240M+ book collection, Librarian displeasure)
- Likelihood: Medium (accessible from corporate network)
- Risk Level: High
- Current Controls: None
- Residual Risk: High
- Mitigation: Network segmentation, restrict to VLAN accessible only from building automation workstation
- Owner: Facilities Manager
- Status: Planned
- Target Date: Q3 2026
- Review Date: Quarterly

RISK-OT-027
- System: Cafeteria HVAC
- Vulnerability: Web interface with default credentials
- Threat: Opportunistic attacker, Script kiddie
- Impact: Low (discomfort, minor energy waste)
- Likelihood: Low (low value target)
- Risk Level: Low
- Current Controls: None
- Residual Risk: Low
- Mitigation: Change default credentials, restrict web interface access
- Owner: Facilities Technician
- Status: Planned
- Target Date: Q4 2026
- Review Date: Annually

The risk register serves multiple purposes:
- Tracks all identified risks in one place
- Shows which risks are being addressed and which are accepted
- Provides evidence of due diligence for regulators and insurers
- Helps prioritise security investments
- Creates accountability with named owners
- Documents decisions for future reference

At UU P&L, the risk register is reviewed quarterly by the security steering committee (Archchancellor, Senior Bursar, OT Engineering Manager, IT Director, Security Consultant). New risks are added, addressed risks are closed, and mitigation progress is tracked.

## Communication strategies for technical risks to non-technical stakeholders

The hardest part of OT security isn't finding vulnerabilities, it's explaining them to people who don't understand technology but need to make decisions about it.

### The challenge of translation

Technical finding:
"The Siemens S7-400 PLCs controlling the turbine governor systems lack authentication mechanisms in the S7comm protocol implementation, allowing any host on VLAN 10 to issue program upload, download, CPU start, and CPU stop commands without credential verification."

What the Archchancellor hears:
"Blah blah technical jargon blah expense blah."

What you need to communicate:
"Anyone who gets access to the turbine network can reprogram or shut down the turbines, causing city-wide blackouts or potentially damaging €18 million turbines."

### Effective communication principles

Avoid jargon
- Don't say: "Exploitation of CVE-2019-13945 allows arbitrary code execution on the HMI workstation"
- Do say: "A known vulnerability allows attackers to take control of the operator screens"

Use concrete examples
- Don't say: "Inadequate network segmentation increases attack surface"
- Do say: "An attacker who compromises any laptop on the university network can reach the reactor controls"

Quantify impact in business terms
- Don't say: "High impact vulnerability"
- Do say: "Could cause €18 million equipment damage plus regulatory fines plus three-month outage"

Compare to familiar risks
- "This is like leaving the reactor building keys in an unlocked drawer in the front office"
- "This is like posting the turbine control system passwords on the university website"

Provide context
- Don't say: "This is a critical vulnerability"
- Do say: "This vulnerability is being actively exploited by ransomware gangs targeting industrial facilities. Three similar organisations were hit in the past year."

Offer clear recommendations
- Don't say: "Implement defence-in-depth security architecture"
- Do say: "We recommend three specific actions: First, restrict network access to control systems. Second, implement monitoring to detect unusual activity. Third, develop incident response procedures. Total cost €180,000, timeline six months."

### Example: Presenting the engineering workstation risk

Bad presentation:
"The engineering workstation exhibits multiple critical vulnerabilities including CVE-2017-0144, lack of endpoint protection, elevated privileges, and insufficient network segmentation, creating a lateral movement vector for advanced persistent threats."

Good presentation:
"The laptop engineers use to program PLCs has serious security problems. It's running Windows 7 with no security updates since 2016, making it vulnerable to common malware. It has no antivirus, and engineers work with full admin rights. This laptop connects to both the corporate network and the control systems.

If an engineer clicks a malicious email attachment, malware could spread to this laptop, then use it as a bridge to the turbine controls. This has happened at other facilities.

The laptop contains all the PLC programs and passwords. If someone steals it, they have the keys to the entire facility.

We need to replace this laptop with a properly secured one, and separate engineering functions from general office work. Cost is €6,000 for the laptop and €12,000 for setup and training. Timeline is two months.

Alternative is accepting that our turbine controls are one phishing email away from compromise."

### Handling objections

"This seems expensive"
Response: "Compare it to the cost of an incident. This mitigation costs €180,000. A ransomware incident at a similar facility last year cost them €2.4 million in ransom, downtime, recovery, and regulatory fines. This is insurance."

"Can't we do this later?"
Response: "The vulnerabilities exist now. Attackers are targeting industrial facilities now. Every day we wait is a day we're exposed. Also, our insurance policy excludes coverage for known vulnerabilities unaddressed for more than 180 days. We've now documented these vulnerabilities, so the clock is ticking."

"Why didn't previous assessments find this?"
Response: "Previous assessments were less thorough, or these vulnerabilities have been introduced since then. The threat landscape evolves. This is why regular assessments are necessary."

"Can't the vendors fix this?"
Response: "Some of these vulnerabilities are in end-of-life products the vendors no longer support. For others, patches exist but require extensive testing before deployment. We can't rely solely on vendors. We need defence in depth."

### The elevator pitch

Sometimes you have 30 seconds to explain why security matters. The elevator pitch for UU P&L:

"Our industrial control systems have vulnerabilities that could allow attackers to cause city-wide power outages or physical damage costing millions. These aren't theoretical risks; similar facilities have been hit by ransomware and nation-state attacks. We need to invest in security to protect the university, the city, and to comply with regulations. It's considerably cheaper than dealing with an incident."

### Visual aids help

Most stakeholders respond better to visuals than text:
- Network diagrams showing attack paths
- Before/after architecture diagrams showing proposed improvements
- Charts showing cost of incidents vs cost of mitigation
- Timeline showing realistic implementation schedule
- Heat maps showing risk levels across systems

At UU P&L, showing a network diagram with red arrows depicting an attack path from "contractor laptop" through "wireless access point" through "engineering workstation" to "turbine PLCs" was more effective than pages of technical findings.

### Follow-up documentation

After presentations, provide written documentation:
- Executive summary (one page, no jargon)
- Management summary (five pages, moderate technical detail)
- Technical report (full details for engineers)
- Remediation roadmap (specific actions, timeline, costs)

Different audiences need different levels of detail. The Archchancellor reads the executive summary. The engineering team reads the technical report. The Senior Bursar reads everything because they need to understand before allocating budget.

### Measuring success

Communication is successful when:
- Stakeholders understand the risks in business terms
- Decisions are made and documented
- Budget is allocated for mitigations
- Timelines are established and followed
- The organisation's security posture improves

Communication fails when:
- Findings are acknowledged but nothing changes
- Decisions are deferred indefinitely
- Budget is promised but never materialised
- Risk acceptance is claimed but not properly documented
- The same vulnerabilities appear in the next assessment

At UU P&L, effective communication led to €300,000 allocated for immediate security improvements, a multi-year security roadmap approved by leadership, and quarterly security reviews established. Not perfect, but measurable progress driven by clear communication of technical risks in business terms.
