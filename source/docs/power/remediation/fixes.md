# Implementing fixes: Turning findings into reality

*Or: Why The Simulator Can't Teach You About Change Management (But Can Teach You Everything Else)*

## The difference between simulation and reality

The UU P&L simulator demonstrates protocol vulnerabilities, exploitation techniques, and attack scenarios. It teaches reconnaissance, vulnerability assessment, and proof of concept development. It's an excellent environment for learning OT security principles without risking actual infrastructure.

What the simulator cannot teach is the organisational, operational, and political reality of actually implementing security improvements in production OT environments.

In the simulator:
- Changes are instant
- Downtime costs nothing
- Failed changes can be rolled back immediately
- Nobody's job depends on uptime
- The university chancellor doesn't receive angry phone calls

In reality:
- Changes require six weeks of planning
- Downtime costs €10,000 per hour
- Failed changes might require physically rewiring equipment
- Everyone's job depends on uptime
- The university chancellor definitely receives angry phone calls

This document explains what happens after you've learned protocol security with the simulator and need to implement improvements in actual facilities.

## What the simulator teaches about fixes

The simulator demonstrates technical remediation:

Protocol security:
- How to configure authentication where possible
- What network segmentation looks like
- How monitoring detects exploitation
- What proper access controls prevent

Vulnerability understanding:
- Why unauthenticated Modbus is exploitable
- How S7 memory reading works
- What anonymous OPC UA allows
- Why protocol diversity increases attack surface

Testing methodology:
- How to verify fixes work
- How to test without breaking systems
- What evidence proves remediation
- How to validate security improvements

What the simulator doesn't teach is the change management, testing procedures, stakeholder communication, and operational coordination required to implement these fixes in production.

## Change management in OT

Change management in IT is often bureaucratic overhead. Change management in OT is operational necessity. The difference is that failed changes in IT might break email for a few hours. Failed changes in OT might shut down production or create safety hazards.

At actual facilities (the sort Ponder worked with after learning on simulators), change management is formalised into effective procedures:

### Change request documentation

Every change requires formal request including:
- What's changing and why
- What systems are affected
- What testing has been done
- What the rollback plan is
- What downtime is required
- Who's responsible

The request template is two pages, which seems bureaucratic until you realise that thinking through these questions before making changes prevents problems.

### Risk assessment

Every change is assessed for:
- Operational risk (could this break production?)
- Safety risk (could this create hazards?)
- Security risk (could this create new vulnerabilities?)

Changes are categorised as low, medium, or high risk with different approval requirements.

### Testing requirements

Low-risk changes (password changes, configuration backups) require verification testing.

Medium-risk changes (firewall rule modifications, VLAN changes) require testing in isolated environment where possible and detailed verification in production.

High-risk changes (network segmentation, major system updates) require formal test plans with acceptance criteria.

### Approval workflow

Low-risk: OT engineer approval

Medium-risk: Senior engineer and operations manager approval

High-risk: Engineering, operations, and management approval plus coordination with facility management

### Maintenance windows

Routine changes happen during scheduled maintenance windows (typically first Sunday of each month, 06:00-14:00). Emergency changes follow expedited process but still require documentation and approval.

The definition of "emergency" must be refined early, otherwise someone will use the emergency process for non-urgent changes on Tuesday afternoon, which goes poorly.

### Change log and audit trail

Every change is documented with before/after configurations, verification test results, and issues encountered. This creates institutional knowledge and makes troubleshooting easier when problems appear weeks later.

The formalised change management adds approximately two hours of paperwork per typical change. It also prevents potentially serious incidents, including proposed firewall changes that would block critical SCADA traffic and VLAN modifications that would isolate HMI systems from the PLCs they control.

Change management is not exciting. It is, however, effective.

## The simulator's role in testing

The simulator provides a safe testing environment for understanding fixes before implementing them in production:

### Protocol configuration testing

Test in simulator:
- Configure S7 password protection
- Implement Modbus filtering
- Test OPC UA authentication
- Verify protocol firewalls work

Verify understanding:
- Does authentication actually block access?
- Do filters prevent exploitation?
- Are there operational impacts?
- What breaks if misconfigured?

Then implement in production:
- With confidence in what configuration does
- With understanding of operational impacts
- With tested rollback procedures
- With verified functionality

### Network segmentation testing

Simulator limitations:
Everything runs on localhost (127.0.0.1). There's no actual network segmentation to test.

What can be learned:
- Which protocols need to communicate
- What traffic patterns are normal
- How to identify necessary connections
- What monitoring looks like

Production implementation:
Real network segmentation requires documenting every network connection, identifying what needs to communicate with what, designing new architecture, creating VLAN structure, defining firewall rules, and planning migration sequence.

This takes weeks in production, but simulator experience teaches which protocols and connections matter, what normal traffic looks like, and how to verify functionality.

### Monitoring and detection testing

The simulator supports detection testing:

[IDS detection testing](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation/ids_detection_test.py) generates attack traffic to test whether detection works.

[SIEM correlation testing](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation/siem_correlation_test.py) generates correlated events to test alert correlation.

Value for production:
- Understanding what attacks look like
- Knowing what should be detected
- Testing detection before deployment
- Verifying monitoring effectiveness

Production monitoring deployment requires coordination, tuning, and sustained testing, but simulator experience provides baseline understanding of what to detect and how.

## Patch testing procedures

Patching in OT is fraught with danger. Patches designed for IT systems often have unexpected effects on OT systems. Vendor patches sometimes break things. And patches can't usually be uninstalled, which means a bad patch might require complete system reinstallation.

The simulator can't teach patch testing (it doesn't simulate Windows Update failures or vendor firmware issues), but it teaches what needs testing:

### What the simulator teaches

Protocol behaviour after changes:
- Does authentication break existing connections?
- Do configuration changes affect functionality?
- Are protocol implementations compatible?
- What happens when things go wrong?

System dependencies:
- Which systems communicate with which others?
- What traffic patterns are normal?
- How to verify functionality?
- What monitoring should show?

### Real facility patch testing procedure

Patch evaluation: Before testing any patch, evaluate what it fixes, what systems it affects, what compatibility issues exist, and what other OT facilities report.

Test environment patching: Where test environments exist (mostly HMI workstations and some network equipment), patches are installed and verified. Test environments match production configuration as closely as possible.

Isolated production testing: For systems without test environments (most PLCs, some SCADA servers), identify an isolated production system for initial testing. This isn't a true test environment but it's better than patching everything simultaneously.

Verification testing: After patch installation, verification includes system boots successfully, all services start correctly, HMI connects to PLCs, SCADA can read sensor data, historical trending works, alarm systems function, backup and restore procedures work.

Staged rollout: Patches are rolled out progressively: test environment, isolated production system, one production system, all production systems. If problems appear at any stage, rollout stops until issues are resolved.

Rollback planning: Every patch has documented rollback procedure. For Windows systems this means system images before patching. For network devices this means configuration backups. For PLCs this means programme backups and documented rollback procedures (which sometimes means "call the vendor and hope").

The patch testing process adds approximately two weeks to the time between "patch released" and "patch deployed to all systems." This seems slow compared to IT environments where patches might be deployed within days. It's appropriately cautious for OT environments where failed patches might shut down power generation.

Lessons are often learnt the hard way. Windows updates that pass all testing sometimes cause HMI software to crash every two hours in production. The problem only appears under sustained load and specific timing conditions that weren't replicated in testing. Rollback procedures work, systems are restored in 30 minutes, incident reports are six pages, and verification testing requirements are expanded to include 48-hour sustained load testing for HMI patches.

## Configuration changes

Most security improvements in OT don't involve patches. They involve configuration changes: firewall rules, network segmentation, access controls, monitoring configurations. These changes are often reversible, which makes them less risky than patches, but they can still break things in creative ways.

The simulator teaches what configurations should look like. Real facilities teach what happens when configurations are wrong.

### Major configuration change projects

At actual facilities, major configuration changes like network segmentation follow careful procedures:

Documentation and planning (6 weeks):
Document every network connection, identify what needs to communicate with what, design new network architecture, create VLAN structure, define firewall rules, plan migration sequence.

This is tedious but essential. Undocumented network connections are discovered, including mysterious systems that nobody can identify but that turn out to be critical for cooling system monitoring.

Preparation (4 weeks):
Procure and install new network equipment, configure VLANs and firewalls in preparation mode (monitoring only, not enforcing), deploy monitoring to verify understanding of traffic patterns.

The monitoring reveals that documentation is approximately 80% accurate and the remaining 20% includes several critical connections that weren't identified.

Staged migration (12 weeks):
Migrate systems to new network architecture one subnet at a time. Start with least critical systems (office network), proceed to more critical systems (monitoring network), complete with most critical systems (control network). Each migration includes verification testing and 48-hour monitoring period before proceeding to next stage.

Firewall enforcement (2 weeks):
Once all systems are migrated and verified, enable firewall enforcement. This is done progressively: block obviously unnecessary traffic first, add specific allow rules for required traffic, monitor for broken functionality.

Verification and documentation (2 weeks):
Comprehensive testing of all functionality, documentation updates, training for operations staff, procedure documentation. Network diagrams are updated to reflect reality, which makes them useful for the first time in years.

Total timeline: Six months
Total downtime: 16 hours spread across three maintenance windows
Total unexpected issues: 23, mostly minor but including three requiring urgent fixes

The most significant issue often appears weeks after migration completion. Library HVAC systems have undocumented connections to power monitoring systems for backup power coordination. Network segmentation breaks this connection. The immediate symptom is HVAC failing to switch to backup power during tests.

The fix is straightforward once the problem is understood: allow specific traffic between office and monitoring networks. The lesson is that documentation is never complete and testing must be thorough and sustained.

## What simulator experience provides

Training on the UU P&L simulator prepares security professionals for real OT security work by teaching:

Protocol understanding:
- How industrial protocols actually work
- What normal traffic looks like
- What attacks look like
- How to verify security controls

Exploitation techniques:
- How to test vulnerabilities safely
- What proof of concept looks like
- How to demonstrate risk without causing harm
- What evidence is convincing

Detection capabilities:
- What attacks should trigger alerts
- How monitoring systems work
- What normal vs suspicious traffic looks like
- How to test detection effectiveness

Remediation approaches:
- What security controls prevent which attacks
- How to configure protocol security
- What network segmentation achieves
- How to verify fixes work

What simulator experience doesn't provide is the organisational skills, change management experience, stakeholder communication ability, and patience required to implement these improvements in production.

## The gap between simulation and reality

The simulator demonstrates that:
- Turbine PLCs accept unauthenticated Modbus commands
- Network segmentation would prevent this
- Monitoring would detect exploitation attempts
- Authentication would require credentials

Real facility implementation requires:
- Six weeks documenting current network architecture
- €150,000 for network equipment
- Four months migrating systems to new architecture
- Coordination with operations for maintenance windows
- Managing stakeholder expectations about timeline and cost
- Explaining to management why this is necessary
- Convincing the engineer six months from retirement to learn new procedures

The simulator teaches technical security. Real facilities teach organisational security. Both are necessary. Neither is sufficient alone.

## Ponder's perspective

Ponder's testing journal included notes about implementation:

"The simulator teaches me what's vulnerable and how to fix it technically. It doesn't teach me how to convince the facilities manager that yes, we really do need a six-month network segmentation project, or how to explain to the operations team that downtime is necessary, or how to write change management documentation that satisfies both bureaucracy and technical accuracy.

"Simulator experience makes me competent at OT security testing. Real facility experience makes me competent at OT security improvement. The first is necessary for understanding what's wrong. The second is necessary for actually making it better.

"The simulator is where you learn to recognise vulnerabilities. Production is where you learn to fix them despite budget constraints, operational requirements, vendor limitations, and the engineer who's been here 30 years and doesn't trust change.

"Train on simulators. Work on reality. Both matter."

## Resources for implementation guidance

The simulator teaches technical OT security. These resources teach implementation:

Change management:
- ITIL change management framework (adapted for OT)
- IEC 62443 change control guidance
- Real facility change management templates

Testing procedures:
- IEC 61511 safety validation procedures
- OT patch testing frameworks
- Configuration testing methodologies

Project management:
- Network segmentation project templates
- Monitoring deployment guides
- Risk management frameworks

Organisational:
- Stakeholder communication guides
- Budget justification templates
- Security awareness training materials

The simulator is the beginning of OT security education, not the end. Use it to understand protocols, learn vulnerabilities, and practise testing. Then apply that knowledge in real facilities where change management, testing procedures, and stakeholder communication determine whether findings become fixes or just interesting reports.

Further reading:
- [Writing Security Reports](pentest-report.md) - Communicating findings effectively
- [Prioritising Remediation](prioritising.md) - Deciding what to fix first
- [Detection Testing](../exploitation/detection.md) - Verifying monitoring works

The simulator teaches what to fix. Real facilities teach how to fix it. Both are essential for effective OT security.
