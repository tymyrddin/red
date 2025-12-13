# The test plan

The document that protects you when things go sideways.

The test plan is your comprehensive blueprint for security testing. It defines what you'll test, how you'll test it, 
when you'll test, who's involved, what could go wrong, and how you'll handle it.

A good test plan protects everyone:

- It protects the testing team by defining clear scope and authorisation
- It protects the client by documenting what to expect and establishing controls
- It protects systems by establishing safety procedures
- It protects the organisation by demonstrating due diligence

A bad test plan (or no test plan) is how security testing becomes security incidents.

## Scope definition (what is in, what is out)

Scope definition is the most critical part of the test plan. Ambiguity in scope leads to misunderstandings, 
unauthorised access, and legal issues.

### In-scope systems

List every system, network, and component that will be tested:

By IP address/network:
- 192.168.10.0/24 (Turbine Control Network)
- 192.168.20.0/24 (Distribution SCADA Network)
- 192.168.30.0/24 (Reactor Control Network)
- 192.168.40.0/24 (Engineering Network)

By system name:
- Turbine PLCs: TURB-PLC-01, TURB-PLC-02, TURB-PLC-03
- Reactor PLCs: REACT-PLC-01, REACT-PLC-02
- SCADA servers: SCADA-PRIMARY, SCADA-BACKUP
- Historian: HISTORIAN-01
- Engineering workstations: ENG-WS-01 through ENG-WS-04
- HMI workstations: HMI-01 through HMI-06
- Distribution RTUs: RTU-SUBSTATION-01 through RTU-SUBSTATION-15

By system type:
- All PLCs in turbine and reactor control (with specific exclusion of safety PLCs)
- SCADA and HMI systems
- Historians and databases
- Engineering workstations
- Network infrastructure (switches, routers) in OT networks

### Explicitly out-of-scope systems

List what is NOT being tested, particularly where there might be ambiguity:

Safety systems:
- Safety PLCs: SAFE-PLC-01, SAFE-PLC-02
- Emergency shutdown systems
- Safety instrumented systems
- (These systems may be observed but not actively tested)

Other organisations' systems:
- Vendor remote access systems (beyond testing security of connections)
- City government systems (connected for monitoring but not owned by UU P&L)
- University corporate IT (separate assessment)

Library systems:
- Library climate control (pending Librarian approval, which has not yet been obtained)

Experimental systems:
- Experimental reactor controls marked "EXPERIMENTAL - DO NOT TOUCH"
- Research PLCs in development lab

External connections:
- Internet-facing systems (separate external assessment)
- Connections to partner organisations

### Grey areas and clarifications

Some systems require clarification:

Engineering workstations that bridge networks: In scope as workstations, but testers will not use them as pivots to access out-of-scope systems without additional approval.

Jump boxes and remote access systems: In scope for authentication and access control testing, but not for use as platforms to access other systems beyond approved scope.

Wireless networks: In scope for identification and testing, but not for use as attack vectors to access out-of-scope systems.

Vendor equipment on-site: In scope if owned/controlled by UU P&L, out of scope if owned by vendors unless vendor provides written authorisation.

At UU P&L, several clarifications were needed:

The alchemical reactor has experimental subsystems: Main reactor controls are in scope, experimental modifications by wizards are out of scope (too unpredictable, wizards don't document their work, risk assessment impossible).

The Library climate control required special handling: Initially listed as in scope, moved to "pending approval" when Librarian responded to approval request by throwing a book at the messenger. Deferred to future assessment pending diplomatic negotiations.

## Asset inventory and dependency mapping

Before testing begins, comprehensive asset inventory and dependency mapping ensures you understand what you're working with.

### Asset inventory requirements

For each in-scope asset, document:

Identification:
- Asset name/hostname
- IP address
- Physical location
- Asset owner/responsible party

Technical details:
- Manufacturer and model
- Firmware/software version
- Operating system (if applicable)
- Protocols supported
- Communication interfaces

Criticality:
- What process/function does it control or monitor?
- What is the impact if it fails or is compromised?
- Are there redundancies or backups?
- What is the recovery time if it needs replacement?

Dependencies:
- What systems does it communicate with?
- What systems depend on it?
- What services does it provide?
- What services does it consume?

### Dependency mapping

Understanding dependencies prevents unintended consequences:

If you test System A and it affects System B, was System B supposed to be affected? Is System B in scope? Is affecting System B acceptable?

At UU P&L, dependency mapping revealed:

The primary SCADA server is a single point of failure for multiple critical functions:
- Operator visibility into turbine operations
- Control of distribution network RTUs
- Data collection for historian
- Alarm management and notification

Testing that affects SCADA server availability impacts all these functions simultaneously. This required special planning: backup SCADA server on standby, testing scheduled during low-risk periods, operators briefed on manual procedures if SCADA becomes unavailable.

The historian database is queried by both OT systems (for trending and analysis) and IT systems (for business reporting):
- Testing historian performance could affect both OT and IT
- OT impacts are in scope, IT impacts might not be
- Coordination with IT required

An engineering workstation has special software licenses:
- Losing this workstation would prevent programming any PLCs
- No spare workstation configured with required software
- Testing this workstation requires extreme caution or use of backup/snapshot

### Creating dependency maps

Dependency maps visualise relationships:

Network topology diagrams showing physical and logical connections. Data flow diagrams showing information flow between systems. Process flow diagrams showing how systems work together to accomplish functions. Failure mode analysis showing cascading effects of system failures.

These maps help:
- Plan testing to minimise unintended impacts
- Predict what might be affected by test activities
- Identify single points of failure
- Understand attack paths
- Plan incident response

At UU P&L, dependency mapping revealed that testing the engineering workstation could impact multiple other systems because:
- It's used to program all PLCs (testing it removes ability to make emergency changes)
- It has vendor VPN software (testing might affect vendor support capability)
- It contains project files used for documentation and training (loss would be significant)
- It bridges OT and IT networks (testing might affect network connectivity)

Resolution: Create full backup before testing, have spare laptop configured and ready, schedule testing when vendor support not needed, ensure operators can function without engineering support during testing period.

## Test windows and blackout periods

Security testing needs time windows when it's safe to test and blackout periods when testing must not occur.

### Defining test windows

At UU P&L, test windows are defined by:

Time of day:
- Preferred: Tuesdays and Thursdays 02:00-06:00 (lowest power demand, maintenance staff on duty, minimal operational activity)
- Acceptable: Weekdays 10:00-15:00 (moderate power demand, full staff available, avoid morning and evening peaks)
- Not preferred: Weekends (minimal staff, harder to get support if needed)

Operational state:
- Preferred: One turbine offline for maintenance (testing can occur on offline turbine with no impact, can observe behaviour when bringing back online)
- Acceptable: All turbines online at partial load (testing less impactful at partial load, more margin for error)
- Avoid: All turbines at or near maximum capacity (high demand, minimal margin, any issues have immediate impacts)

System state:
- Required: All systems functioning normally before testing begins
- Required: No other maintenance or changes in progress
- Required: No known issues or anomalies requiring investigation

Personnel availability:
- Required: OT Engineering Manager available on-site or on-call
- Required: Control room operators on duty
- Preferred: Vendor support available if needed
- Preferred: Maintenance technicians available

### Defining blackout periods

Periods when testing must not occur:

Operational blackouts:
- Peak demand periods: Weekdays 16:00-20:00 (testing might impact ability to meet demand)
- Morning ramp-up: Weekdays 06:00-09:00 (transitioning from night to day operations)
- Scheduled outages: When systems are down for maintenance (can't test systems that aren't running, except very specific testing of offline systems)

Event-based blackouts:
- During extreme weather (demand unpredictable, systems stressed, all attention on operations)
- During incidents or emergencies (obvious)
- During major public events requiring reliable power (sporting events, festivals, Patrician's dinner parties)

Organisational blackouts:
- University holidays when skeleton staff on duty
- Budget approval periods when Archchancellor and Senior Bursar are distracted and irritable
- During external audits or regulatory inspections (testing might be confused with actual issues)

At UU P&L, specific blackouts include:

The last week of term: Students returning home, faculty leaving, campus power demand shifts unpredictably, staff busy with end-of-term activities.

Hogswatch period: Minimal staff, emergency response capabilities reduced, not time for testing that might require emergency response.

The Archchancellor's weekly lunch with the Patrician: No testing that might result in needing to brief the Archchancellor on security issues while the Patrician is present. The Patrician takes keen interest in anything that might affect city operations.

Soul Cake Tuesday: Traditional day of rest for university staff, minimal coverage, testing would be disruptive.

### Dynamic adjustments

Test windows and blackouts may need dynamic adjustment:

If unexpected weather creates high demand, testing pauses. If equipment failure requires emergency maintenance, testing postponed. If key personnel unavailable due to illness, testing rescheduled. If operational anomalies detected, testing delayed until resolved.

The test plan should define who has authority to adjust schedules and how such adjustments are communicated.

## Success criteria and abort conditions

How do you know if testing is successful? When must testing stop?

### Success criteria

Testing is successful if:

Comprehensive coverage achieved:
- All in-scope systems tested according to plan
- All planned test methods executed
- No significant gaps in coverage

Findings documented:
- All vulnerabilities identified and documented
- Risk levels assessed
- Evidence collected
- Recommendations developed

No unintended impacts:
- Testing did not cause operational disruptions
- No equipment damage
- No safety incidents
- Systems functioning normally after testing

Stakeholder objectives met:
- Compliance requirements addressed (NIS2, CNI, etc.)
- Security posture evaluated
- Risks quantified
- Remediation roadmap provided

Knowledge transfer:
- OT staff learned from testing process
- Internal capabilities improved
- Procedures validated or improved

At UU P&L, additional success criterion: "The Librarian remains unaware that testing occurred." This is only partially tongue-in-cheek. If Library systems testing doesn't disrupt Library operations enough for the Librarian to notice, it was conducted appropriately.

### Abort conditions

Testing must stop if:

Safety conditions:
- Any safety system activation
- Any indication of equipment damage or risk
- Any unsafe condition created or discovered

Operational conditions:
- Critical operational issue requires full attention
- System failures unrelated to testing require investigation
- Demand exceeds safe margins for testing to continue

Technical conditions:
- Testing methods proving more disruptive than anticipated
- Unexpected system responses suggesting testing approach is unsafe
- Tools or techniques behaving unpredictably

Personnel conditions:
- Key personnel unavailable
- Communication breakdown
- Coordination failures

External conditions:
- Weather or environmental factors
- External incidents requiring response
- Stakeholder direction to halt

### Abort decision-making

Clear authority for abort decisions:

Immediate abort (anyone can call):
- Safety concerns
- Equipment damage indication
- Loss of control or monitoring

Operational abort (Operations Manager or OT Engineering Manager):
- Operational priorities
- System health concerns
- Resource conflicts

Strategic abort (Archchancellor or Board):
- Business reasons
- External factors
- Risk reassessment

## Communication protocols and escalation chains

Who needs to know what, when, and how?

### Primary communication channels

During testing at UU P&L:

Testing team internal:
- Secure messaging app for coordination
- Shared documentation platform for real-time notes
- Regular team check-ins

Testing team to operations:
- Mobile phone (OT Engineering Manager direct line)
- Control room radio (for urgent coordination)
- In-person (testing team member in control room during high-risk activities)

Testing team to management:
- Email for routine updates
- Mobile phone for urgent issues
- Scheduled briefings for status updates

### Escalation chains

Level 1 (routine coordination):
- Testing team ↔ OT Engineering Manager
- Issues: Scope clarifications, technical questions, scheduling adjustments
- Response time: Within hours

Level 2 (significant concerns):
- Testing team → OT Engineering Manager → Operations Manager/IT Security Manager
- Issues: System anomalies, moderate findings, procedural questions
- Response time: Within 1 hour

Level 3 (serious issues):
- Testing team → OT Engineering Manager → Archchancellor
- Issues: Safety concerns, critical vulnerabilities, incidents
- Response time: Immediate (within 15 minutes)

Level 4 (critical/emergency):
- All stakeholders notified immediately
- Issues: Safety incidents, equipment damage, major operational impacts
- Response time: Immediate

### Notification templates

Routine daily update (email):
```
Daily testing update - [Date]
Systems tested: [List]
Activities performed: [Summary]
Findings: [Brief overview]
Issues/concerns: [Any problems]
Tomorrow's plan: [Next steps]
Status: On track / Behind schedule / Ahead of schedule"

Incident notification (phone + follow-up email):
"Security testing incident - [Severity Level]
Time: [Timestamp]
Systems affected: [List]
What happened: [Brief description]
Current status: [System state]
Actions taken: [What has been done]
Next steps: [What is planned]
Support needed: [What help is required]
```

Critical finding notification (immediate):

```
Critical security finding discovered
System: [Affected system]
Vulnerability: [Brief description]
Potential impact: [What could happen]
Immediate risk: [Is there current threat]
Recommendation: [What should be done now]
Details to follow: [When full report available]
```

## Rollback procedures

What if something goes wrong and systems need to be restored?

### Backup requirements

Before any test that might modify systems:

Configuration backups:
- PLC programs and configurations
- SCADA system configurations
- Network device configurations
- Database schemas and critical data

System state documentation:
- Baseline performance metrics
- Current alarm states
- System health indicators
- Network topology and state

Validation data:
- Test packets to verify normal operation
- Expected responses to known queries
- Performance baselines

At UU P&L, before testing the SCADA server:
- Full database backup
- SCADA application configuration export
- Virtual machine snapshot (SCADA runs on VM)
- Documentation of current system state
- Validation scripts prepared to verify restoration

### Rollback procedures

If systems need restoration:

Immediate rollback (for critical issues):
1. Halt all testing immediately
2. Disconnect testing equipment if necessary
3. Restore from most recent backup
4. Validate restoration
5. Return system to service
6. Investigate cause

Graceful rollback (for non-critical issues):
1. Complete current test activity gracefully
2. Document system state
3. Restore from backup during planned window
4. Validate restoration
5. Document and investigate

### Rollback validation

After restoration:
- System responds to test queries appropriately
- Performance metrics match baseline
- No unexpected alarms or errors
- Operators confirm normal behaviour
- Functions tested and verified
- Extended monitoring for delayed issues

### Rollback authority

Who can authorise rollback?

Immediate rollback for safety/critical issues: Anyone (OT Engineering Manager, Operations Manager, testing team lead)

Planned rollback for non-critical issues: OT Engineering Manager

Decision not to rollback (accept system state): Requires investigation and approval from OT Engineering Manager minimum, possibly escalation to Archchancellor depending on severity.

## Required personnel and their roles

Who needs to be involved and what do they do?

### Testing team roles

Lead tester:
- Overall responsibility for testing execution
- Primary contact for client
- Decision authority for testing team
- Incident response coordination
- Reporting and documentation
- Required qualifications: ICS/SCADA security expertise, 5+ years experience

Technical specialists:
- Perform actual testing activities
- Document findings
- Analyse vulnerabilities
- Support incident response
- Required qualifications: Industrial protocol knowledge, security testing experience

Documentation specialist:
- Real-time documentation of activities
- Evidence collection and management
- Report preparation
- Required qualifications: Technical writing, security documentation

### Client team roles

OT Engineering Manager:
- Primary technical contact for testing team
- Approves daily test activities
- Provides system information and support
- Incident response coordination
- Required availability: On-site or on-call during all testing

Operations Manager:
- Operational oversight
- Authorises testing affecting operations
- Incident response authority
- Required availability: On-call during testing

Control room operators:
- Monitor system health during testing
- Report anomalies immediately
- Execute operational procedures if needed
- Required availability: Normal shift coverage

Maintenance technicians:
- Technical support if needed
- System expertise
- Emergency response capability
- Required availability: On-call during testing windows

IT Security Manager:
- Coordination with IT security
- Network access and monitoring
- Incident response support
- Required availability: On-call during testing

### Support roles

Legal counsel:
- Review of authorisation and contracts
- Advice on legal issues
- Availability: As needed

Insurance representative:
- Risk assessment
- Incident notification
- Availability: Notification contact, emergency contact

Vendor representatives:
- Technical support for vendor equipment
- Emergency support if needed
- Availability: On-call during testing (if contractually required)

### At UU P&L, special roles

Bursar liaison:
- Keep Bursar informed and calm
- Manage Bursar expectations and anxiety
- Translate testing activities into terms Bursar understands
- Required availability: Regular check-ins, immediate availability during incidents
- Required qualifications: Infinite patience

Librarian coordinator (if Library systems ever approved for testing):
- Obtain and maintain Librarian approval
- Monitor Librarian mood
- Immediate abort authority if Librarian displeasure detected
- Required qualifications: Orangutan behavior expertise, fast running speed, knowledge of good hiding places

## Safety precautions

OT security testing can affect physical safety. Precautions are essential.

### Pre-test safety validation

Before testing begins:
- All safety systems verified operational
- Emergency procedures reviewed and understood
- Emergency contact information validated
- Emergency equipment location identified (emergency stops, fire extinguishers, first aid, etc.)
- Evacuation routes known
- Personnel protective equipment available if needed

### During-test safety monitoring

Throughout testing:
- Continuous monitoring of safety system status
- Regular checks on physical equipment condition
- Immediate halt if any safety concerns arise
- Clear communication channels for safety issues
- Authority to stop testing for safety reasons is universal

### Equipment-specific precautions

For turbine testing:
- Monitor vibration and temperature
- Watch for bearing issues
- Be aware of high pressure steam systems
- Know emergency shutdown procedures
- Do not interfere with governor controls without explicit approval and coordination

For reactor testing:
- Monitor containment field strength
- Watch temperature and pressure
- Be aware of alchemical reaction stability
- Know emergency cooling activation procedures
- Never disable safety interlocks
- Keep minimum safe distance
- Have decontamination procedures ready (probably won't be needed, but the one time you don't prepare is the one time you need them)

For electrical systems:
- Be aware of high voltage equipment
- Follow lockout/tagout procedures
- Don't touch anything physically without explicit approval
- Know location of electrical disconnects
- Arc flash hazards in distribution equipment

### Personal safety

Testing personnel should:
- Understand hazards in industrial environment
- Follow all site safety rules
- Wear required PPE
- Never work alone in hazardous areas
- Report safety concerns immediately
- Know when to refuse unsafe activities

At UU P&L, specific safety requirements:
- Hard hats required in turbine hall
- Safety glasses required near rotating equipment
- Hearing protection in high noise areas
- No loose clothing near machinery
- Buddy system for reactor facility access
- Anti-magic amulets when working near alchemical systems (probably doesn't actually work, but makes people feel safer)
- Knowledge of Librarian territorial behavior (avoid Library stacks during feeding times)

## Equipment and tools list

What equipment and tools will be used during testing?

### Hardware

Testing laptops:
- Specifications: Sufficient for running security tools
- Configuration: Hardened, patched, with only required software
- Quantity: One per tester plus one spare
- Security: Full disk encryption, strong authentication

Network adapters:
- Multiple Ethernet adapters for different networks
- Serial adapters for legacy equipment
- Wireless adapters if wireless testing in scope

Network TAPs or span port access:
- For passive traffic capture
- Arranged with network team in advance

Cable testers and tools:
- For verifying network connectivity
- Troubleshooting connection issues

Protocol analysingrs:
- Industrial protocol analysingrs if available
- Vendor-specific tools if required

### Software

Operating systems:
- Testing VMs with required tools pre-configured
- Specific OS versions if required by tools

Security testing tools:
- [Nmap](https://nmap.org/) (network scanning)
- [Wireshark](https://www.wireshark.org/) (protocol analysis with industrial dissectors)
- [Metasploit](https://www.metasploit.com/) (exploitation framework)
- [Burp Suite](https://portswigger.net/burp) (web application testing)
- [Snap7](http://snap7.sourceforge.net/) (Siemens S7 testing)
- [pyModbus](https://github.com/pymodbus-dev/pymodbus) (Modbus testing)
- Industrial-specific tools as needed

Documentation tools:
- Note-taking applications
- Screenshot and screen recording tools
- Diagramming software
- Report templates

### Vendor-specific tools

Engineering software:
- Siemens TIA Portal or STEP 7 (for analysing S7 PLCs)
- Rockwell Studio 5000 (for analysing Allen-Bradley PLCs)
- SCADA configuration tools (for analysing SCADA configurations)
- Note: Properly licensed versions, not pirated software

Protocol libraries:
- Vendor-specific protocol implementations
- Open-source industrial protocol libraries

### Tool approval process

All tools must be:
- Listed in test plan
- Approved by client before use
- Verified as working correctly
- Used only as specified in test plan

Unapproved tools must not be used without explicit additional authorisation.

At UU P&L, tool approval included:
- Review of tool descriptions and capabilities
- Demonstration of tool behavior on test system
- Agreement on how tools will be used
- Restrictions on specific tool features (e.g., nmap rate limits, Metasploit exploit module restrictions)

## Legal and contractual sign-offs

The test plan requires formal approvals before execution.

### Required approvals

Technical approval:
- OT Engineering Manager: Confirms technical feasibility and safety of test plan
- IT Security Manager: Confirms coordination with IT security and network teams

Operational approval:
- Operations Manager: Confirms test plan is operationally acceptable and schedule works

Safety approval:
- Safety Manager/Officer: Confirms safety precautions are adequate and risks are acceptable

Legal approval:
- Legal Counsel: Confirms authorisation is proper, contracts are in order, compliance requirements met

Executive approval:
- Archchancellor: Overall approval authority, accepts risks, authorises testing

Board approval (if required):
- Board of Governors: For high-risk testing affecting critical systems or with significant potential impact

### Signature authority

Each approval must be signed by person with actual authority:
- Not delegates unless delegation is explicitly documented
- Original signatures on legal documents (digital signatures acceptable if legally equivalent)
- Date of signature recorded
- Any conditions or caveats documented

### Conditional approvals

If approval is conditional:
- Conditions clearly documented
- Verification that conditions are met before testing proceeds
- Sign-off that conditions satisfied

At UU P&L, the Archchancellor's approval was conditional:
*"Approved subject to: (1) Successful completion of test run on simulator, (2) Verification that backup systems are operational, (3) Notification to city emergency services completed, (4) The Bursar having been properly medicated."*

Each condition was verified and documented before testing began.

### Documentation package

Complete documentation package includes:
- Test plan (this document)
- Rules of engagement
- Authorisation letter
- Contract between parties
- Statement of work
- Insurance certificates
- All required approvals with signatures
- Risk assessment
- Safety plan
- Communication plan
- Incident response plan

This package is the legal and technical foundation for testing. Keep complete copies with testing team, client, and in secure storage.

## UU P&L example test plan highlights

The complete test plan for UU P&L included several notable provisions:

### Scope peculiarities

"Testing will include turbine control systems, reactor control systems (excluding experimental modifications by wizards), distribution SCADA, and associated engineering workstations and HMIs. Library climate control is explicitly out of scope pending successful completion of diplomatic negotiations with the Librarian. The Librarian has indicated that unauthorised testing of Library systems may result in physical consequences for testers."

### Scheduling considerations

"Testing may only occur during the weekly maintenance window (Tuesdays 02:00-04:00) when the Bursar is asleep and cannot panic-induced interference occur. Additionally, testing must avoid the Archchancellor's weekly lunch with the Patrician (Fridays 12:00-14:00), as any incidents during this period would be particularly awkward to explain."

### Special abort conditions

"Testing will immediately cease if: (1) Any safety system activates, (2) The Librarian is observed anywhere near systems being tested, (3) The Bursar wakes up and asks what is happening, (4) Anything begins glowing in a way that suggests imminent magical discharge, (5) The ghosts in the cellars start complaining about network traffic (this has happened before)."

### Success criteria

"Testing will be considered successful if: (1) All planned test activities completed, (2) Comprehensive security assessment delivered, (3) No equipment damaged, (4) No safety incidents occurred, (5) The Librarian remains unaware testing happened, (6) The city maintains continuous power, (7) The Patrician does not need to be informed of any incidents."

### Incident response special provisions

"In the event of incident affecting Library systems (should they ever be approved for testing): (1) Immediately activate emergency cooling, (2) Evacuate Library vicinity, (3) Notify Librarian (from safe distance), (4) Prepare generous offering of bananas, (5) Have medical team on standby (for testers, not for Librarian), (6) Update résumés (for testers)."

These provisions sound humorous but reflect real risk factors at UU P&L: the unpredictable nature of experimental systems, the importance of stakeholder management, the variety of hazards in a university that combines technology and magic, and the absolute necessity of keeping certain stakeholders (Librarian, Patrician) satisfied.

The test plan ultimately ran to 127 pages including appendices. It was approved after three revisions and extensive negotiations. Testing proceeded safely and successfully, findings were documented and communicated, remediation is ongoing, and most importantly, the Librarian never noticed.

Which is precisely how OT security testing should work.
