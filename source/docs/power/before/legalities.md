# Legal frameworks and compliance

The paperwork that keeps you out of prison.

Security testing industrial control systems occupies an uncomfortable legal grey area. You're being paid to break 
into systems, identify vulnerabilities, and demonstrate how attackers could cause physical damage. Without proper 
legal authorisation, this is indistinguishable from actual cybercrime.

The difference between "legitimate security testing" and "unauthorised access with intent to damage critical 
infrastructure" is entirely down to paperwork. Very specific, very carefully worded paperwork.

This section covers the legal frameworks that apply to OT security testing, how to get authorisation that actually 
protects you, and why "the CEO said it was fine" isn't sufficient legal cover when you're working with systems that 
could explode.

## EU NIS2 Directive

The [Network and Information Security Directive 2 (NIS2)](https://purple.tymyrddin.dev/docs/audits/nis2/) came into 
force in January 2023, replacing the original NIS Directive. It significantly expands the scope of entities covered 
and strengthens security requirements.

### Who's covered

NIS2 applies to "essential entities" and "important entities" across multiple sectors:

Essential entities include:
- Energy (electricity, oil, gas, hydrogen)
- Transport (air, rail, water, road)
- Banking and financial market infrastructures
- Health sector
- Drinking water and wastewater
- Digital infrastructure
- ICT service management
- Public administration
- Space

Important entities include:
- Postal and courier services
- Waste management
- Chemicals production
- Food production and distribution
- Manufacturing (medical devices, computers, machinery, motor vehicles, other transport equipment)
- Digital providers
- Research organisations

At UU P&L, as an electricity provider for A'Morpork, they are definitely an essential entity. The alchemical reactor, 
being experimental, adds extra complexity.

### Security requirements under NIS2

Entities must implement risk management measures including:

- Policies on risk analysis and information system security
- Incident handling
- Business continuity and crisis management
- Supply chain security (including security in supplier relationships)
- Security in network and information systems acquisition, development, and maintenance
- Policies and procedures to assess effectiveness of security measures
- Basic cyber hygiene practices and cybersecurity training
- Policies and procedures regarding cryptography and encryption
- Human resources security, access control policies, and asset management
- Use of multi-factor authentication or continuous authentication solutions
- Secured voice, video, and text communications and emergency communication systems where appropriate

### Penalties for non-compliance

This is where NIS2 gets serious:

For essential entities:
- Administrative fines up to €10 million or 2% of total worldwide annual turnover (whichever is higher)
- Management can be held personally liable
- Temporary bans on management holding positions

For important entities:
- Administrative fines up to €7 million or 1.4% of total worldwide annual turnover (whichever is higher)

These penalties apply not just for security breaches but for:
- Failing to implement required security measures
- Not reporting incidents within required timeframes (24 hours for initial notification, 72 hours for detailed report)
- Not cooperating with authorities
- Providing incomplete or incorrect information

### What this means for security testing

NIS2 makes security assessments effectively mandatory. Organisations must *"test the effectiveness of their security 
measures"*. This means:

- Regular penetration testing is now a legal requirement, not a nice-to-have. At UU P&L, they can't simply decide security testing is too expensive or risky. The law requires it.
- Testing must be comprehensive. You can't just test corporate IT and ignore OT. The electricity generation and distribution systems are explicitly in scope.
- Findings must be addressed. You can't just do assessments for compliance theatre. Identified risks must be mitigated or formally accepted with documented justification.
- Management is personally liable. The Archchancellor can't delegate responsibility to the IT department and claim ignorance if things go wrong.

This actually helps security teams. *"NIS2 requires this"* is a powerful argument when requesting budget or approval for testing.

## UK CNI regulations

The UK has its own critical national infrastructure (CNI) protection regime, separate from but overlapping with NIS2.

### CNI sectors

The UK government defines 13 CNI sectors:
- Chemicals
- Civil nuclear
- Communications
- Defence
- Emergency services
- Energy
- Finance
- Food
- Government
- Health
- Space
- Transport
- Water

Each sector has lead government departments responsible for resilience and security.

### Security requirements

CNI operators must:
- Meet baseline security standards appropriate to their risk level
- Report significant cyber incidents to the National Cyber Security Centre (NCSC)
- Undergo regular security assessments
- Implement recommendations from security assessments
- Participate in cross-sector information sharing
- Maintain incident response capabilities

For UU P&L, being an energy provider, they fall under Department for Energy Security and Net Zero oversight. They must:

Report incidents within specified timeframes (hours, not days). Participate in sector-specific threat intelligence sharing. Implement NCSC guidance (including the Industrial Control System Security guidance). Allow periodic assessments by government security agencies.

## The Computer Misuse Act 1990

This is the UK law that makes hacking illegal. It's also the law that makes penetration testing legally complicated.

The Act creates three main offences:

Section 1: Unauthorised access to computer material
- Maximum sentence: 2 years imprisonment and/or unlimited fine
- This is "simple" hacking without authorisation

Section 2: Unauthorised access with intent to commit further offences
- Maximum sentence: 5 years imprisonment and/or unlimited fine
- This is hacking with intent to commit fraud, damage, etc.

Section 3: Unauthorised modification of computer material
- Maximum sentence: 10 years imprisonment and/or unlimited fine
- This includes deleting files, changing configurations, uploading malware

Section 3ZA: Unauthorised acts causing serious damage
- Maximum sentence: 14 years imprisonment (or life imprisonment if damage to human welfare, environment, economy, or national security, or if it endangers life)
- This is the really scary one for OT security testing

### Why Section 3ZA matters for OT testing

This section specifically addresses attacks on computer systems that cause or create risk of:
- Damage to human welfare (including loss of essential services like power)
- Damage to the environment
- Damage to the economy
- Damage to national security
- Loss of life or serious illness or injury

Testing industrial control systems at UU P&L potentially falls under this if:
- You send commands to PLCs controlling turbines (risk to power supply)
- You interact with reactor controls (environmental risk, risk to life)
- You test city distribution SCADA (impact on economy and essential services)

Without proper authorisation, even read-only testing could theoretically be prosecuted under Section 3ZA if it could be argued you created a risk to critical systems.

### The "authorised" defence

The Computer Misuse Act includes a defence: you're not guilty if you had permission from the person entitled to give it.

The critical questions are:
- Who is "entitled to give" permission?
- What constitutes valid permission?
- Does permission cover what you actually did?

For UU P&L:
- The Archchancellor, as head of the organisation, can authorise testing
- But can they authorise testing that might affect city-wide power? (The city isn't their asset)
- Does verbal permission suffice, or do you need written authorisation?
- If authorisation says "test the network", does that include sending commands to PLCs?

## IEC 62443 standards

[IEC 62443](https://purple.tymyrddin.dev/docs/audits/iec62443/) is the international standard for industrial 
automation and control systems security. It's not a legal requirement in most places, but it's increasingly referenced 
in contracts, regulations, and as best practice.

### The IEC 62443 series

The standard is organised into four groups:

General (62443-1-x):
- Concepts, terminology, metrics

Policies and procedures (62443-2-x):
- Security program requirements for asset owners
- Requirements for IACS service providers
- Patch management requirements

System (62443-3-x):
- Security technologies for IACS
- System security requirements and security levels

Component (62443-4-x):
- Secure product development lifecycle requirements
- Technical security requirements for IACS components

### Security levels (SL)

IEC 62443 defines security levels from SL 1 to SL 4:

SL 1: Protection against casual or coincidental violation
- Attacker: Someone with minimal skills, resources, and motivation
- Example: Preventing accidental misconfigurations

SL 2: Protection against intentional violation using simple means
- Attacker: Someone with low skill, low resources, generic tools
- Example: Script kiddies, opportunistic attackers

SL 3: Protection against intentional violation using sophisticated means
- Attacker: Someone with moderate to high skills, moderate resources, IACS-specific tools
- Example: Organised crime, disgruntled insiders with knowledge

SL 4: Protection against intentional violation using sophisticated means with extended resources
- Attacker: Someone with high skills, extensive resources, sophisticated tools, possibly nation state
- Example: Advanced persistent threats, nation state actors

At UU P&L:
- Building HVAC might only require SL 1
- Turbine controls probably require SL 2-3
- Reactor safety systems might warrant SL 3-4
- City distribution SCADA should be SL 3

### Zones and conduits

IEC 62443-3-2 defines network architecture in terms of:

Zones: Groups of assets with similar security requirements
- Each zone has a defined security level
- Assets in a zone trust each other (relatively)

Conduits: Communication paths between zones
- Each conduit is a potential attack vector
- Must be protected appropriate to the security levels being connected

For UU P&L's architecture:
- Corporate IT: One zone (maybe SL 1-2)
- SCADA and HMIs: One zone (SL 2-3)
- PLCs and field devices: One or more zones (SL 2-3)
- Safety systems: Separate zone (SL 3-4)
- Conduits between zones: Protected by firewalls, monitored, logged

### Why IEC 62443 matters for testing

When planning security tests:

- The standard defines what security controls should exist. Your testing verifies they're actually implemented. If UU P&L claims SL 2 for turbine controls, your testing should verify they meet SL 2 technical requirements.
- The standard provides a framework for discussing security. Instead of arguing about whether specific controls are necessary, you reference the required security level and corresponding requirements.
- The standard is recognised by regulators and insurers. "We're implementing IEC 62443 SL 2 controls" carries more weight than "we're doing some security stuff".
- The standard includes security testing requirements. IEC 62443-2-4 specifies requirements for security service providers, including penetration testing methodologies.

## GDPR considerations in OT environments

Yes, even in OT environments in A'Morpork.

The General Data Protection Regulation (GDPR) applies to personal data wherever it's processed. OT environments 
contain more personal data than you might think:

### Personal data in OT systems

Employee records:
- HR systems (often on the same network as OT)
- Training records
- Access credentials

Access control data:
- Badge access logs showing who entered where and when
- Biometric access systems
- Timestamps of control room access

Video surveillance:
- Control rooms are often under video surveillance
- Substation cameras capture people's faces
- Footage is stored for security/investigation purposes

Engineering workstation data:
- Personal files and documents
- Email archives
- Web browsing history

Historian data:
- Operator actions are logged with usernames
- Maintenance activities include technician identities
- Alarm acknowledgements are attributed to individuals

At UU P&L:
- Access control system logs every engineer who enters the turbine hall
- Control room video surveillance runs 24/7
- SCADA system logs every operator action with username and timestamp
- Engineering workstations contain personal emails and files
- Maintenance system tracks which technician worked on which equipment

All of this is personal data under GDPR.

### GDPR requirements that affect security testing

When conducting security assessments, you may access personal data. This creates obligations:

- Legal basis for processing: You need a lawful basis to access personal data during testing. Typically this is "legitimate interest" (security assessment) or contractual necessity.
- Data minimisation: Access only the personal data necessary for testing. If you can test without accessing personal data, do so.
- Security of processing: Ironic but important. You must protect personal data you access during testing. Don't copy personal data to insecure systems, don't include it in reports unnecessarily, delete it when testing is complete.
- Data protection impact assessment (DPIA): Security testing that involves extensive personal data processing may require a DPIA.

### GDPR breach implications

If a cyber incident affects personal data: 

- Breach notification to supervisory authority within 72 hours. 
- Notification to affected individuals "without undue delay" if high risk to their rights. 
- Potential fines up to €20 million or 4% of annual global turnover (whichever is higher).

For UU P&L, a ransomware incident that encrypts or exfiltrates personal data triggers GDPR breach notification. 
This adds urgency to incident response.

The security testing report should identify personal data at risk and include GDPR breach potential in impact 
assessments.

## Getting legal authorisation that actually protects you

Verbal permission from a manager isn't sufficient legal protection. You need written authorisation that's specific, 
comprehensive, and signed by someone with authority.

### Who can authorise testing

The person authorising testing must have authority over the systems being tested. For UU P&L:

The Archchancellor can authorise testing of university systems. But can they authorise testing that might affect 
city-wide power distribution? Probably not unilaterally.

This is resolved by:
- Board approval for high-risk testing (city distribution SCADA)
- Notification to relevant authorities (city emergency services, regulatory bodies)
- Coordination with stakeholders (city government, major customers)
- Insurance company notification

For lower-risk testing (engineering workstations, HMIs), the OT Engineering Manager can probably authorise.

### What authorisation must include

Effective authorisation specifies:

Scope: Exactly what systems, networks, and assets are in scope
- IP address ranges
- Specific systems by name
- Protocols that may be tested
- Types of testing permitted (passive reconnaissance, active scanning, vulnerability testing, etc.)

What you're authorised to do:
- Query systems for configuration and status (read operations)
- Attempt authentication with provided credentials
- Attempt authentication with common default credentials
- Download PLC programs for analysis
- Test web applications for common vulnerabilities
- Perform network scanning (with specified rate limits)

What you're not authorised to do:
- Upload modified programs to production PLCs
- Send commands that change physical state
- Perform denial of service testing on production systems
- Access safety systems beyond observation
- Test during blackout periods

Timeframe: When testing is authorised
- Specific dates and times
- Exclusion periods (peak demand, maintenance activities)

Personnel: Who is authorised to conduct testing
- Named individuals
- Or roles ("employees of XYZ Security Ltd")

Reporting: What and when to report
- Immediate notification of critical findings
- Escalation procedures if problems occur
- Final report delivery timeline

Liability and insurance: Who's responsible if something goes wrong
- Testing firm's insurance coverage
- UU P&L's acceptance of residual risk
- Indemnification clauses

### Example authorisation clause for UU P&L

Bad authorisation: *"You are authorised to perform security testing of our network."*

This is dangerously vague. What network? What kind of testing? When?

Good authorisation reads something like this one: 

```
\[Testing Firm] is authorised to conduct security assessment of Unseen University 
Power & Light Co. industrial control systems as follows:

In scope:
- IP ranges 192.168.10.0/24 (Turbine Control), 192.168.20.0/24 (Distribution SCADA), 
  192.168.30.0/24 (Reactor Controls)
- Engineering workstations ENG-WS-01 through ENG-WS-04
- SCADA servers SCADA-PRIMARY and SCADA-BACKUP
- HMI workstations in main control room

Authorised activities:
- Passive network reconnaissance and traffic analysis
- Active network scanning at rates not exceeding 100 packets/second
- Enumeration of PLCs, RTUs, and SCADA components
- Reading PLC configurations and programs (download only, no upload)
- Testing authentication on HMIs and engineering workstations using provided test 
  credentials and common default credentials
- Web application security testing of SCADA and HMI web interfaces
- Social engineering testing of specified personnel (list attached)

Specifically prohibited activities:
- Any write operations to production PLCs
- Any commands that affect physical equipment state
- Any interaction with safety systems beyond passive observation
- Denial of service testing
- Testing during blackout periods (weekdays 16:00-20:00, weekends, holidays)
- Testing without prior coordination with on-site OT Engineering Manager

Time period:
- Testing authorised from 1 March 2026 to 31 March 2026
- Daily test windows: Weekdays 02:00-06:00 and 10:00-15:00
- Each test activity requires day-of approval from OT Engineering Manager

Authorised personnel:
- \[Named testers from Testing Firm]
- Must present authorisation letter and photo ID upon request

Incident reporting:
- Immediate notification (within 1 hour) to OT Engineering Manager for any finding 
  that creates immediate risk
- Daily brief summary of activities and preliminary findings
- Final report within 2 weeks of test completion

This authorisation is signed by \[Archchancellor], approved by Board of Governors 
\[date], with notification provided to \[City Emergency Services, National Cyber 
Security Centre, Insurance Provider].

Signed: \[Archchancellor]
Date: \[Date]
Witness: \[Senior Bursar]
```

Specific, comprehensive, and clearly defines boundaries. If something goes wrong, we can point to exactly 
what we were authorised to do.

### The authorisation letter protects everyone

- For the testing firm: It's your defence if accused of unauthorised access. "I had written permission" is a complete defence under Computer Misuse Act if the permission was validly given.
- For UU P&L: It documents what was agreed. If testers exceed their authority, the letter proves it. If something breaks during testing, the letter shows what was known and accepted.
- For law enforcement: If an incident occurs, the letter distinguishes legitimate testing from actual attacks.
- For insurers: It shows due diligence in managing security testing risks.

Keep the original authorisation letter with you during testing. If questioned by law enforcement, building security, or anyone else, you can immediately produce evidence of authorisation.

## What "authorised" really means

Having an authorisation letter does not mean you can not still end up in legal trouble. Authorisation has limits.

### Exceeding authorisation

If your authorisation letter says `test systems in IP range 192.168.10.0/24` and you find an interesting system 
at `192.168.50.15`, you cannot test it without explicit additional authorisation.

If authorised for `passive reconnaissance` and you find a vulnerability that is tempting to exploit, you cannot 
exploit it without additional authorisation.

Exceeding your authorisation, even slightly, potentially makes your actions `unauthorised access`.

### Scope creep during testing

During testing at UU P&L, you discover:
- The engineering workstation (in scope) has remote access to vendor systems (not in scope)
- The SCADA system (in scope) has connections to a sister facility in Pseudopolis (not in scope)
- The network (in scope) has unexpected wireless access points (not previously known)

Can you test these?

The cautious answer: Stop and ask. Document what you found, notify the client, request additional authorisation or 
clarification before proceeding.

The legally risky answer: *"It's all connected, so it's all in scope."* This is how you end up explaining to law 
enforcement why you accessed systems you weren't explicitly authorised to access.

### When authorisation might not protect you

Even with authorisation, you might face legal issues if:

- You cause damage through negligence. Authorisation to test does not authorise reckless behaviour that causes unnecessary damage.
- You exceed the scope of authorisation. If you stray outside documented boundaries, that's unauthorised access.
- The person who authorised you did not have authority. If a junior engineer authorised you to test systems they don't control, that authorisation might not be valid.
- You discover criminal activity and participate in it. If you find evidence of insider fraud and continue testing in ways that facilitate it, you might be considered complicit.
- You access particularly sensitive data unnecessarily. Even with general authorisation, accessing highly sensitive personal data, trade secrets, or national security information might require specific additional authorisation.

### Cross-border considerations

UU P&L's systems include connections to facilities in other countries. This creates legal complications:

- If you're physically in one country but testing systems in another country, whose laws apply? Probably both. You might need authorisation that complies with both local and foreign legal requirements.
- If testing involves data transfers across borders, data protection laws of both jurisdictions apply.
- If you are a foreign tester working for a local Ankh Morpork client, visa and work authorisation issues may arise. Some countries require specific licenses for security testing work.

For UU P&L's international connections, the authorisation letter explicitly addresses:

- Which international systems are in scope
- Acknowledgment that testing crosses borders
- Confirmation that appropriate foreign authorisations have been obtained
- Compliance with relevant foreign laws

### Professional insurance and liability

Even with perfect authorisation, things can go wrong. Professional indemnity insurance is essential.

Your insurance should cover:

- Professional negligence (you made a mistake causing damage)
- Errors and omissions (you missed something in testing)
- Cyber liability (your testing caused a cyber incident)
- Defence costs (legal costs if sued or prosecuted)

Check your insurance policy carefully:

- Does it cover OT/ICS testing specifically? (Many cyber insurance policies are written for IT security and might not cover industrial systems)
- What are the exclusions? (Some policies exclude damage to physical property)
- What are the limits? (Are they sufficient if you accidentally cause millions in damage?)
- Does it cover criminal defence costs? (If you're prosecuted under Computer Misuse Act, legal defence is expensive)

UU P&L should also have cyber insurance covering security testing activities. The testing contract should specify:

- Each party's insurance requirements
- Indemnification provisions
- Liability limits
- Who's responsible for what types of damages

### Contracts and statements of work

In addition to the authorisation letter, you need a contract covering:

Scope of work: What testing will be performed (high level). Payment terms. Confidentiality and non-disclosure. 
Intellectual property (who owns the findings, the report, any tools developed). Liability and indemnification. 
Insurance requirements. Dispute resolution.

And a statement of work covering: Detailed technical scope. Methodology. Deliverables. Timeline. Personnel. 
Assumptions and constraints. Acceptance criteria.

The authorisation letter, contract, and statement of work form a complete legal framework for testing. Together 
they define what you'll do, who's paying for it, who's liable if things go wrong, and what happens to the results.

At UU P&L, the complete documentation package included:
- Board resolution authorising security assessment
- Contract between UU P&L and testing firm
- Statement of work with technical details
- Authorisation letter with specific permissions
- Non-disclosure agreement
- Insurance certificates from both parties
- Notification letters to relevant authorities and stakeholders

This seems like excessive bureaucracy. It is. But it's the bureaucracy that keeps you out of prison and protects 
everyone if something goes wrong.

