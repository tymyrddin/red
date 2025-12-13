# Business policies and governance

Making sure everyone knows what "don't break the factory" means in practice.

Legal authorisation gives you permission to test. Business policies ensure everyone understands how testing will be 
conducted, what's expected, and what happens if things don't go according to plan.

Without clear policies and governance, you end up with chaos. Engineers panicking when they see unusual network 
traffic. Operators uncertain whether to call security when they see unfamiliar people with laptops. Management 
surprised by test activities despite having approved them.

Good policies and governance make security testing a controlled, understood, managed process rather than a 
terrifying surprise.

## Developing an OT security testing policy

UU P&L needs a policy that addresses OT security testing specifically. Their general IT security policy does not 
cover the unique risks and requirements of testing industrial control systems.

### Policy scope and applicability

The policy should specify:

What it covers:
- All security testing of OT systems, networks, and components
- Including PLCs, SCADA, HMIs, historians, engineering workstations, RTUs, IEDs
- Whether conducted by internal teams, external consultants, or vendors

Who it applies to:
- Anyone conducting security testing of OT systems
- OT personnel supporting security testing
- Management approving security testing
- Incident response teams who might interact with testing activities

### Authority and approval requirements

The policy must specify who can authorise testing:

Low-risk testing (passive reconnaissance, documentation review):
- OT Engineering Manager can approve
- Notification to operations team

Medium-risk testing (active scanning at safe rates, authentication testing, web application testing):
- OT Engineering Manager and IT Security Manager jointly approve
- Notification to operations team and management
- Scheduling coordinated with operations

High-risk testing (anything involving production PLCs, safety systems, testing during operational periods):
- Board-level approval required
- Comprehensive risk assessment
- Detailed test plan
- Incident response procedures
- Insurance verification
- Notification to all relevant stakeholders

### Testing requirements

The policy should mandate:

Pre-test requirements:
- Detailed test plan submitted and approved
- Risk assessment completed
- Rules of engagement documented
- Personnel training and qualifications verified
- Insurance certificates provided
- Legal authorisation obtained
- Technical coordination meeting held
- Rollback procedures documented
- Communication protocols established

During-test requirements:
- Real-time coordination with operations
- Continuous monitoring of system health
- Immediate reporting of anomalies
- Adherence to approved scope and methods
- Daily activity logging
- Abort procedures if problems detected

Post-test requirements:
- Validation that systems are functioning normally
- Preliminary findings briefing within 24 hours
- Full report within agreed timeline
- Recommendations for remediation
- Lessons learned session
- Policy update if needed

### Safety and operational constraints

The policy must address OT-specific constraints:

Prohibited activities:
- Testing without approved test plan
- Exceeding authorised scope
- Testing during blackout periods without emergency approval
- Interacting with safety systems beyond approved observation
- Performing denial of service testing on production systems
- Using tools or techniques not approved in test plan

Required precautions:
- Rate limiting on network scans
- Coordination before each test activity
- On-site OT personnel present during high-risk tests
- Abort procedures defined and understood
- Rollback capability verified before tests begin
- System backups completed before any write-operations (even in test environments)

### Incident handling during testing

The policy must address what happens if things go wrong:

Defining incidents:
- System performance degradation
- Unexpected alarms or shutdowns
- Loss of monitoring or control
- Equipment behaving abnormally
- Safety system activations
- Any other unexpected effects on physical processes

Response procedures:
- Immediate halt of testing activities
- Notification to operations and management
- System health check procedures
- Determination whether incident is test-related
- Documentation of incident
- Decision process for resuming testing

Responsibility and liability:
- Who's responsible for monitoring system health
- Who has authority to abort testing
- How incidents are investigated
- How liability is determined

At UU P&L, the policy includes:

A specific section on the Library climate control: "Testing of Library environmental systems requires direct approval from the Librarian. This approval must be obtained in person, with appropriate offerings of bananas. Remote approval is not acceptable. The Librarian's mood must be assessed before proceeding. Testing will be immediately aborted if the Librarian appears displeased."

This sounds humorous, but it's actually recognition that the Librarian has better situational awareness of Library systems than anyone else, and their cooperation is essential.

## Rules of engagement for industrial systems

Rules of engagement (RoE) specify exactly how testing will be conducted. They're more detailed than the policy, specific to each assessment.

### Technical boundaries

IP addresses and networks in scope (with subnet masks and descriptions). Systems in scope by hostname or description. Protocols that may be tested. Ports that may be scanned. Scan rates and timing constraints.

Out of scope: Emergency systems unless specifically approved. Safety systems beyond passive observation. Production systems during blackout periods. Any system not explicitly listed as in-scope.

### Testing methods and constraints

Passive reconnaissance: Approved without limit (network sniffing, documentation review, observation).

Active reconnaissance: Approved with constraints:
- Network scanning at maximum 100 packets/second
- Protocol-specific tools (Modbus polling, DNP3 queries) at rates not exceeding normal operational traffic
- Banner grabbing and service enumeration

Vulnerability testing: Approved for identified systems with constraint:
- No exploitation without specific approval for each vulnerability
- Proof-of-concept only, demonstrate capability without executing

Authentication testing: Approved:
- Using provided test credentials
- Using default credentials from public sources
- No brute-force attacks
- No password cracking beyond testing weak/default passwords

Social engineering: Requires specific approval:
- Phishing tests must be pre-coordinated
- Physical security testing must be scheduled
- Specific personnel must be identified as targets
- No vishing (voice phishing) to emergency services or safety personnel

### Operational coordination

Daily check-in: Before starting each day's testing, coordinate with OT Engineering Manager. Confirm systems are stable, no maintenance planned, no operational issues.

Real-time coordination: Before each significant test activity (scanning new network, testing new system, attempting exploitation), notify operations and wait for acknowledgement.

Continuous monitoring: Operations team monitors system health throughout testing. Testing team monitors for unexpected responses. Either party can call immediate halt if concerns arise.

End-of-day validation: At end of each testing session, validate systems are functioning normally before leaving.

### Communication protocols

Primary contact: OT Engineering Manager (mobile: +XXX, email: xxx, on-site location: Control Room).

Secondary contact: IT Security Manager (mobile: +XXX, email: xxx).

Emergency contact: Archchancellor's office (mobile: +XXX).

On-call operations: +XXX (24/7 for emergencies).

Communication channels:
- Primary: Mobile phone (for immediate issues)
- Secondary: Email (for non-urgent coordination)
- In-person: Control room (for complex discussions)

### Escalation procedures

Level 1 (Minor issues): Testing causes minor performance impact, unexpected alarms (non-critical), uncertainty about scope.

*Response: Pause testing, consult with OT Engineering Manager, document issue, proceed if resolved.*

Level 2 (Significant issues): Testing causes system malfunction, critical alarms, loss of monitoring/control, safety system activation.

*Response: Immediately halt testing, notify OT Engineering Manager and operations, investigate cause, document incident, formal decision required before resuming.*

Level 3 (Critical issues): Testing causes safety incident, equipment damage, service disruption, injury risk.

*Response: Immediately halt testing, activate emergency procedures, notify all stakeholders including Archchancellor, full investigation, testing suspended pending investigation.*

### Abort criteria

Testing must be immediately halted if:
- Any safety system activates
- Any equipment exhibits abnormal behaviour
- Any critical alarms are triggered
- Operations team requests halt
- System performance degrades significantly
- Testers are uncertain whether activity is safe
- Rollback procedures prove inadequate
- Communication with operations is lost
- Any incident rated Level 2 or above occurs

After halt, testing may not resume without explicit approval from OT Engineering Manager (Level 1) or Archchancellor (Level 2-3).

### Documentation requirements

The RoE requires comprehensive documentation:

- Daily activity logs: What systems were tested, what methods were used, what was discovered, any anomalies or incidents.
- Real-time notes: Timestamp each significant activity, record system responses, document coordination with operations.
- Evidence collection: Screenshots, packet captures, tool outputs (sanitised of sensitive data).
- Incident reports: Detailed documentation of any anomalies, including timeline, impact, cause, resolution.

At UU P&L, the RoE includes specific provisions:

*"Testing of turbine control systems will be conducted on Tuesday mornings 02:00-04:00 during scheduled light-load 
periods. Operations will manually balance load to compensate if testing affects turbine output. Backup turbines will 
be on standby. City emergency services will be notified of testing schedule in case of unexpected outage."*

*"Testing of alchemical reactor controls will be conducted only when reactor is in cold shutdown state. Reactor will 
not be started until 24 hours after testing completes and all systems are validated as functioning correctly. 
The Bursar will be sedated for the duration of testing to prevent panic-induced interference."*

## Change management integration

Security testing is a change to the operational environment, even if you're not changing configurations. It must 
integrate with change management processes.

### Registering testing as a change

At UU P&L, all changes to OT systems go through formal change management:

Change request submitted:
- Description: Security assessment of turbine control systems
- Systems affected: List of in-scope systems
- Potential impact: Network traffic increase, possible performance degradation
- Risk level: Medium
- Rollback plan: Halt testing if issues occur
- Testing schedule: Proposed dates and times

Change review:
- Technical review by OT engineering team
- Operational review by operations team
- Risk assessment by safety team
- Approval by Change Advisory Board

Change scheduling:
- Coordinated with maintenance windows where possible
- Blackout periods identified and avoided
- Dependencies identified (other planned changes, operational requirements)
- Resources allocated (personnel, equipment, support)

Change implementation:
- Daily coordination as testing progresses
- Monitoring for unexpected impacts
- Documentation of activities

Change validation:
- Post-test validation that systems function normally
- Sign-off from operations that no issues remain
- Change record updated with actual activities and results

Change closure:
- Lessons learned documented
- Recommendations fed into future change planning
- Metrics captured (what worked, what didn't)

### Coordinating with other changes

Security testing must be coordinated with other planned changes:

- If maintenance is scheduled on systems being tested, either reschedule testing or reschedule maintenance. Testing creates uncertainty about system state; maintenance creates controlled changes. Combining them makes troubleshooting impossible if something goes wrong.
- If configuration changes are planned, complete and validate them before testing, or schedule testing well after changes are stabilised. Testing a recently changed system makes it unclear whether issues are from the change or from testing.
- If vendor work is scheduled, coordinate carefully. Vendor remote access during security testing creates confusion. Is unusual traffic from testing or from vendor? Best to separate activities.

At UU P&L, the change management system flagged conflicts:
- Security testing scheduled for turbines on 15 March
- Vendor maintenance scheduled for turbines on 15 March
- Conflict: Reschedule one activity
- Resolution: Vendor maintenance moved to 8 March, security testing proceeds 15 March after systems have been validated post-maintenance

### Emergency change procedures

If critical security issues are discovered during testing requiring immediate action:

Emergency change request raised. Expedited review process (via phone/email rather than waiting for Change Advisory 
Board meeting). Risk assessment focuses on risk of not fixing vs risk of emergency change. Implementation during 
operational period may be approved if risk is high enough.

At UU P&L, testing discovered that contractor VPN credentials were shared and never rotated, allowing unauthorised 
access. Emergency change request to disable VPN access and implement new credential management was approved within 
2 hours. The alternative (leaving critical vulnerability exposed for weeks until next scheduled change window) was 
unacceptable.

## Business continuity planning

Security testing could potentially cause outages. Business continuity plans must account for this possibility.

### Testing impact on business continuity

Well-designed testing minimises impact, but can't eliminate all risk:

Possible impacts from testing:
- Performance degradation during intensive scanning
- Accidental system crashes from malformed packets
- False positive alarms creating operator workload
- Resource consumption on monitored systems
- Network congestion
- In rare cases, actual failures

Business continuity plans must address:
- How to maintain operations if testing causes issues
- When to activate backup systems
- How to communicate with stakeholders
- How to restore normal operations

### Testing the business continuity plan

Security testing provides opportunity to validate business continuity capabilities:

If testing causes an outage (ideally planned, or at least managed), does the business continuity plan work? Can 
operations switch to backup systems? Do communication procedures function? Do escalation chains work?

At UU P&L, one test deliberately (with full coordination and approval) caused the primary SCADA server to become 
unavailable. This validated:

- Operators could switch to backup SCADA server (successfully, 45 seconds)
- Alarm notifications worked (successfully)
- Communication to management worked (successfully)
- Escalation to vendors worked (but slower than expected; procedures updated)

This "test within a test" provided valuable validation of business continuity capabilities whilst security testing 
was ongoing with full support infrastructure in place.

### Planning for worst-case scenarios

Despite all precautions, worst-case scenarios must be planned for:

What if testing causes extended outage?
- How is power restored to the city?
- What backup generation is available?
- How are critical customers notified?
- How is damage controlled (reputational, financial)?

What if testing causes equipment damage?
- How is damaged equipment isolated?
- What spare parts are available?
- How long to repair/replace?
- Who pays for damage? (Insurance, contract terms)

What if testing causes safety incident?
- Emergency response procedures
- Evacuation plans
- Incident investigation
- Regulatory notifications
- Public communications

At UU P&L, the worst-case scenario plan for testing included:
- Pre-positioning backup generation capacity
- Notifying city emergency services of testing schedule
- Having spare critical components on-site
- Emergency contact lists validated and current
- Incident response team on standby
- PR team prepared with communication templates

None of this was needed. But having plans provided confidence to proceed with testing, knowing that even worst-case 
scenarios had planned responses.

## Incident response procedures

Incident response procedures for security testing differ from normal incident response because you know the cause: 
it is probably the testing.

### Incident classification during testing

Is this incident related to testing or coincidental?

Related to testing:
- Timing correlates with test activities
- Affects systems being tested
- Stops when testing stops
- Testing team observed unusual responses

Coincidental:
- Timing doesn't correlate with testing
- Affects systems not being tested
- Testing was paused when incident occurred
- Known unrelated cause (maintenance, equipment failure)

Uncertain:
- Timing is ambiguous
- Could be either testing-related or coincidental
- Need investigation to determine

At UU P&L, during testing an alarm activated on a turbine PLC. Investigation revealed:
- Alarm was for low bearing oil pressure
- Testing was occurring on turbine control network
- But test activity was passive monitoring, no commands sent
- Oil pressure sensor had failed (unrelated to testing)
- Coincidental timing created initial confusion

Incident was classified as coincidental, testing continued after validation that it was unrelated.

### Response procedures for test-related incidents

If incident is testing-related:

Immediate actions:
1. Halt all testing activities immediately
2. Notify operations and OT Engineering Manager
3. Document system state and test activities leading to incident
4. Do not attempt to "fix" anything without coordination

Investigation:
1. What test activity was occurring when incident happened?
2. What was the system response?
3. What systems were affected?
4. What is the current state of systems?
5. Are systems safe/stable?

Resolution:
1. If systems are not safe/stable, emergency response procedures take priority over testing considerations
2. If systems are safe/stable, methodical investigation to determine root cause
3. Restore systems to normal state (or as close as possible)
4. Validate restoration before any resumption of testing

Documentation:
1. Timeline of events
2. Test activities performed
3. System responses observed
4. Investigation findings
5. Remediation actions taken
6. Lessons learned
7. Recommendations for preventing recurrence

Decision to resume:
1. Root cause understood
2. Systems fully restored and validated
3. Test plan modified to prevent recurrence
4. Risk re-assessed and accepted
5. Formal approval to resume from appropriate authority

### Incident reporting requirements

During testing, incident reporting has additional requirements:

Internal reporting:
- Immediate notification to OT Engineering Manager (all incidents)
- Notification to Archchancellor (Level 2-3 incidents)
- Notification to Board (Level 3 incidents)

External reporting:
- Insurance notification (incidents that might result in claims)
- Regulatory notification (if incident meets reporting thresholds)
- Vendor notification (if incident affects systems under vendor support contracts)

Testing firm reporting:
- Detailed incident report to client
- Professional indemnity insurance notification
- Professional body notification (if required by professional standards)

At UU P&L, a test-related incident would trigger:
- Immediate internal notification (within 1 hour)
- Insurance notification (within 24 hours if potential claim)
- Regulatory notification (within required timeframe if threshold met)
- Detailed written incident report (within 48 hours)
- Lessons learned session (within 1 week)

## Stakeholder communication plans

Security testing involves many stakeholders with different information needs.

### Identifying stakeholders

For UU P&L security testing:

Executive stakeholders:
- Archchancellor (overall authority and accountability)
- Senior Bursar (budget and financial risk)
- Board of Governors (governance oversight)

Information needs: High-level overview, major risks, costs, timeline, business impacts, significant findings.

Communication frequency: Initial briefing before testing, weekly status updates, immediate notification of critical 
findings or incidents, final presentation of results.

Operational stakeholders:
- OT Engineering Manager (technical coordination)
- Operations Manager (operational impacts)
- Control room operators (day-to-day coordination)
- Maintenance team (systems knowledge and support)

Information needs: Detailed technical plans, daily schedules, real-time coordination, immediate notification of any issues.

Communication frequency: Daily or more often.

Support stakeholders:
- IT Security team (coordination, overlap with IT systems)
- Facilities team (physical access, environmental systems)
- Legal team (authorisation, compliance)
- Insurance provider (risk management)

Information needs: Relevant aspects of testing affecting their areas, coordination requirements, findings relevant to their responsibilities.

Communication frequency: As needed, periodic updates.

External stakeholders:
- City government (potential service impacts)
- Emergency services (notification of testing schedule)
- Major customers (service level agreements)
- Regulatory authorities (compliance and notification requirements)
- Vendors (coordination of access and support)

Information needs: Potential impacts on their interests, schedule of testing that might affect them, results relevant to their concerns.

Communication frequency: Initial notification, updates if significant impacts, final results summary.

### Communication methods and templates

Different stakeholders need different communication approaches:

- Executive briefings: PowerPoint presentations, one-page executive summaries, focus on business impacts and risks.
- Technical coordination: Email, instant messaging, phone calls, in-person meetings, detailed technical documentation.
- Operational coordination: Radio communications, in-person in control room, immediate and informal.
- Formal reporting: Written reports, structured formats, comprehensive documentation.

### Communication schedule for UU P&L

Pre-testing:
- T-30 days: Proposal and initial briefing to Archchancellor and Board
- T-14 days: Detailed technical planning meeting with OT Engineering and operations
- T-7 days: Notification to external stakeholders (city government, emergency services)
- T-3 days: Final coordination meeting, validation of plans and procedures
- T-1 day: Confirmation that all preparations complete, final go/no-go decision

During testing:
- Daily: Morning coordination meeting with OT Engineering and operations
- Daily: End-of-day summary email to Archchancellor and key stakeholders
- Real-time: Immediate notification of any incidents or critical findings
- Weekly: Status update presentation to executive stakeholders

Post-testing:
- T+1 day: Preliminary findings briefing to OT Engineering
- T+3 days: Initial findings presentation to Archchancellor and Board
- T+14 days: Draft report delivered for review
- T+21 days: Final report delivered
- T+30 days: Remediation planning meeting
- T+90 days: Follow-up review of remediation progress

### Managing expectations

Clear communication manages expectations:

- Testing will find vulnerabilities. That's the point. Finding vulnerabilities doesn't mean the OT team is incompetent; it means security testing is working.
- Not all findings require immediate action. Risk-based prioritisation determines what's critical vs what can be addressed over time.
- Some findings may have no practical fix. Legacy equipment with inherent vulnerabilities might require compensating controls rather than patches.
- Testing is disruptive despite best efforts. Some operational friction is inevitable and acceptable.

At UU P&L, managing the Bursar's expectations was particularly important. The Bursar tends towards panic when anything unusual happens. Clear, calm, factual communication helped: "We're conducting scheduled security testing this week. You may see unusual activity in logs or hear about test activities. This is expected and controlled. We'll notify you immediately if anything unexpected occurs."

## When to stop testing (abort criteria)

Knowing when to stop testing is as important as knowing how to test. Clear abort criteria prevent testing from 
causing serious problems.

### Automatic abort triggers

Testing must stop immediately if:

- Safety system activation: Any safety system activates, whether related to testing or not. Do not proceed until cause is understood and systems are validated.
- Equipment damage indication: Any indication of physical equipment damage or abnormal behaviour suggesting imminent damage.
- Loss of monitoring or control: If operators lose visibility or control of systems, testing stops until restored.
- Critical alarms: Any critical alarm that suggests safety risk or equipment damage risk.
- Communication loss: If communication between testing team and operations is lost, testing stops until re-established.
- Unauthorised access detected: If actual attack is suspected during testing, testing stops to avoid confusion with real incident.

### Judgment-based abort triggers

Testing should stop if:

- System performance degradation: Systems are responding slower, more errors, reduced capacity. May indicate testing is stressing systems beyond safe limits.
- Uncertainty about safety: If testing team is uncertain whether an activity is safe, stop and consult before proceeding.
- Scope ambiguity: If it's unclear whether a system or activity is in scope, stop and clarify.
- Procedural deviation: If testing deviates from approved plan, stop and get approval for deviation.
- Personnel availability: If key personnel (OT Engineering Manager, operations support) become unavailable, testing pauses until coverage is restored.
- Environmental factors: If environmental conditions change (weather affecting systems, power demand changes, other priorities emerge), testing may need to pause.

### The abort decision authority

Who can call for testing to stop?

- Anyone can call immediate halt for safety reasons. If anyone believes continuing testing creates safety risk, they can call immediate halt. Authority to resume testing requires formal approval, but authority to stop is universal.
- OT Engineering Manager can halt testing for technical or operational reasons.
- Operations Manager can halt testing for operational reasons.
- Testing team lead can halt testing if conditions don't match test plan assumptions.
- Archchancellor (or designee) can halt testing for any reason.

At UU P&L, during testing a control room operator noticed slightly unusual PLC CPU utilisation. Not an alarm, not 
clearly problematic, but unusual. Operator called for pause in testing. Investigation revealed testing scan rate 
was higher than intended (configuration error). Scan rate corrected, testing resumed after validation. The operator's 
judgment call prevented potential issues.

### Resume criteria after abort

After testing is halted, resuming requires:

1. Root cause understood: Why was testing halted? What was the concern?
2. Issue resolved: Whatever triggered halt has been addressed.
3. Systems validated: All affected systems checked and confirmed functioning normally.
4. Test plan updated: If halt revealed issue with test plan, plan is updated before resuming.
5. Risk re-assessed: Is it safe to continue? What mitigation prevents recurrence?

Approval obtained: Appropriate authority approves resumption (OT Engineering Manager minimum, escalate to 
Archchancellor for serious halts).

### Graceful test termination

Even if no abort conditions occur, testing should end gracefully:

- Complete current activity: Don't leave tests half-finished.
- Return systems to known state: Ensure all systems are stable before leaving.
- Validation checks: Verify systems are functioning normally.
- Documentation: Complete activity logs and notes.
- Communication: Notify stakeholders that testing session is ending.

Secure workspace: Remove testing equipment, secure access points used, ensure physical security restored.

At UU P&L, end-of-day termination procedure includes:

1. Complete and document final test activity
2. Run validation checks on all tested systems
3. Review any anomalies or concerns with operations
4. Send end-of-day summary email
5. Secure testing equipment
6. Sign out of facility access logs
7. Confirm with operations that all is well before leaving

## Post-test validation requirements

After testing completes, validation ensures systems are functioning normally and nothing was inadvertently changed or 
broken.

### Immediate post-test validation

Within 24 hours of test completion:

System health checks:
- All in-scope systems respond normally
- No unexpected alarms or warnings
- Performance metrics within normal ranges
- Communications functioning
- Monitoring systems show expected status

Configuration verification:
- Configurations match pre-test baselines
- No unauthorised changes detected
- All test accounts/credentials removed or disabled
- Any test data cleaned up

Operational validation:
- Operations team confirms systems behaving normally
- No operator concerns or anomalies
- Control capabilities confirmed
- Historical data review shows no gaps or anomalies

### Extended post-test monitoring

For 7-14 days after testing:

- Increased monitoring: Watch for delayed effects, subtle changes, or issues that weren't immediately apparent.
- Operator feedback: Collect any concerns or observations from operators.
- Performance trending: Monitor performance metrics for changes from baseline.
- Incident correlation: If incidents occur, investigate whether they could be delayed effects of testing.

At UU P&L, post-test monitoring once revealed an issue that wasn't immediately apparent. Three days after testing, a PLC experienced intermittent communication errors. Investigation revealed testing had exposed a marginal network switch that was beginning to fail. The switch had been working but unreliably; testing network traffic pushed it past marginal state. The switch was replaced, issue resolved. Without extended monitoring, this would have been difficult to diagnose.

### Validation reporting

Post-test validation results are documented:

Validation report includes:
- Systems validated and methods used
- Any anomalies detected
- Any changes found
- Any concerns raised by operations
- Confirmation that systems are functioning normally (or identification of issues requiring attention)

This report closes out the testing activity and confirms safe completion.
