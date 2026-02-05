# Remediation deep dive: From Findings to Fixes

*The most important part of the full-day simulation*

## Why remediation matters more than discovery

Finding vulnerabilities in OT systems is straightforward. Industrial protocols have minimal security. Network access 
typically means full control. A competent pentester can discover critical vulnerabilities in hours.

The hard part: Getting those vulnerabilities fixed.

This requires:
- Understanding business context
- Quantifying risk in business terms
- Prioritising based on multiple factors
- Planning implementation considering operational constraints
- Convincing stakeholders to fund and execute
- Following through to completion

This is where most security assessments fail. Reports get written, filed, and forgotten. Vulnerabilities remain 
unfixed. The next pentester finds the same issues.

This simulation emphasises remediation to break that cycle.

## The remediation framework

Based on the resources at https://red.tymyrddin.dev/docs/power/remediation/, this framework has three phases:

### Phase 1: Understanding findings (Report writing)
### Phase 2: Prioritizing action (Risk-based prioritization)
### Phase 3: Planning implementation (Practical fixes)

Let's explore each in detail as it applies to the UU P&L scenario.

---

## Phase 1: Writing the penetration test report

### Report structure

Based on industry best practice and the remediation framework, security assessment reports have layers for different audiences.

#### Executive summary (1-2 pages)

Purpose: Enable non-technical decision-makers to understand scope, risk, and required action

Required elements:

1. Engagement overview
- What was assessed (UU P&L control systems)
- When assessment occurred
- What methodology was used (nation-state threat actor perspective)
- What access was provided (network-adjacent, no credentials)

2. High-level findings
- Number of findings by severity (X critical, Y high, Z medium, W low)
- Most significant findings in business language
- "Anyone on your network can remotely control all three turbines without passwords"
- "Complete control logic and operational data can be exfiltrated in under 10 minutes"
- "Safety systems accessible via same unauthenticated protocols as production systems"

3. Business impact summary
Translate technical findings into business consequences:
- Operational risk: Unplanned shutdowns, equipment damage, service interruptions
- Financial risk: €10,000/hour downtime, equipment replacement costs, regulatory fines
- Safety risk: Ability to bypass safety interlocks, manipulation of safety-critical parameters
- Reputational risk: Power disruption to Palace, Watch, Mint - Patrician's attention, University reputation
- Strategic risk: Intelligence gathering enables future attacks, positioning for leverage

4. Recommendations summary
- Quick wins (0-30 days, €8,000)
- Medium-term improvements (30-90 days, €45,000)
- Strategic initiatives (6-12 months, €500,000)
- Expected risk reduction for each tier

5. Bottom line
Clear statement: "This facility is vulnerable to remote control by anyone with network access. Immediate action required on Tier 1 recommendations. Strategic planning required for network segmentation."

Archchancellor test: Can Ridcully read this and understand the problem without technical background?

Patrician test: Does this answer "So what?" and "Why should I care?"

#### Technical findings (bulk of report)

Each finding follows consistent structure. Use this template:

Finding title: [Descriptive name]
Severity: [Critical/High/Medium/Low with justification]
CVSS score: [If applicable]
Affected systems: [Specific devices/protocols]
Discovery method: [How you found it]

Description:
What is the vulnerability? Explain in technical terms but clearly.

Example:
"The Modbus TCP protocol implementation on all three turbine PLCs accepts unauthenticated read and write commands from any network-connected device. The protocol specification includes no authentication mechanism. Any client that can establish TCP connection on port 502 can read or modify any holding register, coil, or input register."

Technical details:
- Protocol specifics
- Register/memory addresses accessed
- Commands executed
- Tools used

Evidence:
- Screenshots showing access
- Log outputs
- Script execution results
- Video demonstrations

Impact: What can an attacker do with this? Be specific.

Example: An attacker can:
- Read current turbine speeds, pressure, and temperature values
- Modify speed setpoints, causing turbine overspeed conditions
- Trigger emergency shutdown via coil manipulation
- Exfiltrate operational baselines for later attack optimisation
- Maintain persistent access for long-term intelligence gathering

Worst-case scenario: What's the maximum possible damage?

Example: *"A sophisticated attacker could simultaneously target all three turbines during peak demand, causing complete facility shutdown. Restart procedures take 4+ hours. This would disrupt power to Patrician's Palace, Watch House, and Guild District, affecting critical city functions."*

Business impact: Translate to stakeholder language.

Example: Unplanned shutdown during winter peak demand could:
- Cost €40,000 in lost generation revenue (4 hours × €10,000/hour)
- Risk equipment damage from improper shutdown sequences (€2M replacement cost)
- Violate power supply agreements with the city (contractual penalties)
- Require emergency explanation to the Patrician (political consequences)
- Damage University reputation as reliable infrastructure provider

Likelihood: How probable is exploitation?

Example: High. The network includes:
- Connection to University corporate network (potential lateral movement from compromised workstation)
- Vendor remote access capabilities (supply chain risk)
- Engineering workstations with dual network connections (bridging risk)
- No network segmentation between administrative and control systems

Exploitation requires only network access and knowledge of Modbus protocol. Tools are freely available. No exploits 
or sophistication required.

Remediation recommendations: Specific, actionable steps to fix the issue.

Example:
1. Immediate (0-30 days):
   - Deploy Modbus firewall rules limiting access to authorized HMI and engineering workstations (IP whitelisting)
   - Implement network monitoring to detect unauthorised Modbus connections
   - Document all legitimate Modbus clients for baseline

2. Medium-term (30-90 days):
   - Deploy jump host for all administrative access to control systems
   - Implement VLANs separating control traffic from administrative traffic
   - Establish change management procedures for firewall rules

3. Strategic (6-12 months):
   - Implement complete network segmentation following IEC 62443 zone model
   - Evaluate Modbus/TCP gateway with authentication capabilities
   - Deploy industrial IDS with protocol-aware detection rules

References:
- Industry standards (IEC 62443, NIST CSF)
- Similar incidents or advisories
- Vendor documentation
- Best practices

Repeat this structure for each finding. Typical OT assessment: 15-30 findings.

#### Remediation roadmap (3-5 pages)

This is where prioritisation happens. Don't just list findings by severity. Organise by implementation strategy.

Tier 1: Immediate actions (0-30 days)

Objective: Stop opportunistic attacks, gain visibility, buy time for strategic planning

Example recommendations for UU P&L:

1. Change/set passwords on all systems supporting authentication
   - Effort: 8 hours
   - Cost: Internal labour only
   - Risk reduction: Prevents opportunistic attacks exploiting default credentials
   - Operations impact: Minimal (can be done during normal operations)
   - Owner: Blue team + Operations

2. Remove unauthorized vendor remote access, establish approval process
   - Effort: 16 hours
   - Cost: Process documentation + training
   - Risk reduction: Eliminates unmanaged entry point
   - Operations impact: Requires vendor coordination for future access
   - Owner: Operations Director

3. Deploy network monitoring at key points (Wireshark captures or industrial IDS trial)
   - Effort: 24 hours (setup and baseline)
   - Cost: €5,000 (trial licenses)
   - Risk reduction: Enables attack detection
   - Operations impact: None (passive monitoring)
   - Owner: Blue team

4. Implement firewall rules restricting OPC UA access to known HMIs
   - Effort: 8 hours (rule development + testing)
   - Cost: Internal labour
   - Risk reduction: Limits SCADA attack surface
   - Operations impact: Minimal if tested properly
   - Owner: Blue team with Operations approval

Total Tier 1: ~56 hours, €5,000-8,000, 1 month timeline

Expected risk reduction: 30% (stops unsophisticated attacks, enables detection)

Tier 2: Medium-term improvements (30-90 days)

Objective: Establish security architecture, create defensive layers, build security processes

Example recommendations for UU P&L:

1. Deploy jump host for all administrative access to OT systems
   - Effort: 40 hours (implementation + testing + procedures)
   - Cost: €15,000 (hardware + software)
   - Risk reduction: Centralises access control, enables monitoring
   - Operations impact: Changes admin workflows (training required)
   - Owner: Blue team, operations buy-in required

2. Implement authentication on OPC UA servers (security mode: SignAndEncrypt)
   - Effort: 32 hours (configuration + certificate management + testing)
   - Cost: €8,000 (PKI infrastructure or certificates)
   - Risk reduction: Eliminates anonymous SCADA access
   - Operations impact: HMIs must be reconfigured (requires brief outages)
   - Owner: Blue team + SCADA vendor

3. Establish formal change management for OT systems
   - Effort: 40 hours (process development + training + documentation)
   - Cost: Internal labour
   - Risk reduction: Prevents security degradation, improves stability
   - Operations impact: Adds process overhead (but improves safety)
   - Owner: Operations Director with Blue team support

4. Conduct security awareness training (OT-specific)
   - Effort: 16 hours (content development + delivery)
   - Cost: €10,000 (external training provider)
   - Risk reduction: Reduces social engineering and user error risk
   - Operations impact: Staff time for training (1 day per person)
   - Owner: HR + Blue team

Total Tier 2: ~128 hours, €33,000-45,000, 3 months timeline

Expected risk reduction: Additional 35% (architectural improvements, process maturity)

Tier 3: Strategic initiatives (6-12 months)

Objective: Fundamental security architecture, sustainable security program

Example recommendations for UU P&L:

1. Network segmentation (IEC 62443 zones and conduits)
   - Effort: 400+ hours across multiple teams
   - Cost: €350,000 (firewalls, switches, engineering time, testing, cutover)
   - Risk reduction: Fundamentally limits attack surface and lateral movement
   - Operations impact: Multiple planned outages (32+ hours across maintenance windows)
   - Implementation: 6-month project in phases
   - Owner: Joint Operations + Blue team + external consultants

   Phased approach:
   - Phase 1: Corporate IT / OT separation (month 1-2)
   - Phase 2: Safety system isolation (month 3-4)
   - Phase 3: Control system zoning by function (month 5-6)
   - Phase 4: Industrial DMZ for remote access (month 6+)

2. Industrial IDS/IPS deployment with OT protocol support
   - Effort: 120 hours (selection, deployment, tuning, training)
   - Cost: €80,000 (sensors + management + 1st year licenses)
   - Risk reduction: Detection and prevention of protocol-level attacks
   - Operations impact: None if deployed in monitoring mode initially
   - Implementation: 3-month project
   - Owner: Blue team with vendor support

3. SIEM integration for OT events
   - Effort: 80 hours (integration, correlation rules, dashboards, procedures)
   - Cost: €40,000 (SIEM expansion + OT log sources + integration)
   - Risk reduction: Correlation across IT and OT, incident response enablement
   - Operations impact: Minimal (backend systems)
   - Implementation: 2-month project after IDS deployment
   - Owner: Blue team + SOC

4. Vendor security requirements in procurement and contracts
   - Effort: 40 hours (policy development + legal review + rollout)
   - Cost: €10,000 (legal review + policy documentation)
   - Risk reduction: Reduces supply chain risk for future acquisitions
   - Operations impact: Affects vendor selection and contracting
   - Implementation: 1-month policy development, ongoing enforcement
   - Owner: University Procurement + Blue team

5. Annual red team assessment program
   - Effort: External engagement
   - Cost: €20,000/year (external red team)
   - Risk reduction: Continuous validation of security posture
   - Operations impact: Minimal (controlled testing)
   - Implementation: Ongoing annual program
   - Owner: CISO

Total Tier 3: €500,000, 12-month timeline

Expected risk reduction: Additional 30% (comprehensive defense-in-depth)

Cumulative risk reduction after all tiers: ~95% (residual risk managed through monitoring and response)

## Phase 2: Prioritisation workshop

During the afternoon session, all teams work together to prioritise findings using the framework.

### The prioritisation matrix

For each finding, assess across five dimensions:

#### 1. Safety impact (1-5 scale)

5 - Critical safety impact:
- Ability to disable safety interlocks
- Direct control of safety-critical systems
- Could cause injury or fatality

Example: Unauthenticated access to safety PLC

4 - High safety impact:
- Could trigger unsafe conditions indirectly
- Affects safety-adjacent systems
- Degraded safety response capability

Example: Ability to cause turbine overspeed beyond safety margins

3 - Moderate safety impact:
- Affects monitoring of safety parameters
- Could delay safety response
- No direct safety control

Example: SCADA data manipulation affecting operator awareness

2 - Low safety impact:
- Affects non-safety-critical systems only
- Safety systems independent
- No plausible safety scenario

Example: Unauthorized access to historian data

1 - No safety impact:
- Cannot affect physical processes
- Information disclosure only

Example: Network architecture documentation accessible

#### 2. Operational impact (1-5 scale)

5 - Critical operational impact:
- Complete facility shutdown possible
- Equipment damage likely
- Multi-day recovery

Example: Simultaneous attack on all three turbines

4 - High operational impact:
- Single system shutdown
- Significant revenue loss
- Hours to days recovery

Example: Individual turbine emergency stop

3 - Moderate operational impact:
- Degraded operations
- No immediate shutdown
- Reduced efficiency or capacity

Example: Setpoint manipulation causing suboptimal operation

2 - Low operational impact:
- Nuisance disruptions
- Quick recovery
- Minimal revenue impact

Example: HMI connectivity issues

1 - No operational impact:
- No disruption to operations
- Backend systems only

Example: Exfiltration of non-critical data

#### 3. Exploitation likelihood (1-5 scale)

5 - Exploitation highly likely:
- System internet-accessible or easily reachable from compromised workstation
- No authentication required
- Freely available tools
- Low sophistication required

Example: Unauthenticated Modbus access from corporate network

4 - Exploitation likely:
- Requires network access (achievable via phishing/lateral movement)
- Minimal authentication easily bypassed
- Public exploits available

Example: Default credentials on engineering workstation

3 - Exploitation possible:
- Requires insider access or sustained effort
- Some authentication required
- Moderate sophistication needed

Example: S7 PLC access requiring knowledge of rack/slot addressing

2 - Exploitation unlikely:
- Requires combination of access and specialized knowledge
- Multiple barriers
- High sophistication required

Example: Exploitation requiring custom firmware analysis

1 - Exploitation very unlikely:
- Requires physical access
- Highly specialized knowledge
- No known exploitation paths

Example: Vulnerability in air-gapped system backup process

#### 4. Business impact (1-5 scale)

Consider financial, regulatory, and reputational consequences:

5 - Critical business impact:
- €1M+ financial exposure
- Regulatory fines likely
- Major reputational damage
- Patrician-level attention

Example: Extended outage affecting Palace and city services

4 - High business impact:
- €100K-1M financial exposure
- Regulatory reporting required
- Significant reputational risk
- University Council involvement

Example: Public disclosure of inadequate critical infrastructure security

3 - Moderate business impact:
- €10K-100K financial exposure
- Insurance deductible range
- Moderate reputational impact

Example: Brief unplanned outage requiring customer notifications

2 - Low business impact:
- <€10K financial exposure
- Minor reputational impact
- Internal concern only

Example: Delayed maintenance due to security investigation

1 - Minimal business impact:
- Negligible financial impact
- No reputational impact

Example: Technical control gap in non-critical system

#### 5. Remediation feasibility (1-5 scale, inverted)

Note: Higher score = easier to remediate (inverted from risk scores)

5 - Very easy to remediate:
- Configuration change only
- No downtime required
- Low or no cost
- Days to implement

Example: Setting passwords on systems with authentication support

4 - Easy to remediate:
- Minor process or configuration changes
- Brief downtime acceptable
- <€10K cost
- Weeks to implement

Example: Deploying firewall rules with testing

3 - Moderate remediation:
- Requires planning and testing
- Scheduled downtime needed
- €10-50K cost
- Months to implement

Example: Jump host deployment with access policy changes

2 - Difficult to remediate:
- Significant project required
- Multiple stakeholder coordination
- €50-250K cost
- 6+ months to implement

Example: VLAN segmentation requiring switch upgrades

1 - Very difficult to remediate:
- Major architecture change
- Extended planning and outages
- €250K+ cost
- 12+ months to implement

Example: Complete network segmentation with zone architecture

### Calculating priority score

For each finding:

Risk score = (Safety × 2) + (Operational × 1.5) + (Likelihood × 1.5) + (Business × 1)

Priority score = Risk score / Remediation feasibility

Result: Higher priority score = more urgent remediation

### Example prioritization

Finding: Unauthenticated Modbus access to turbine PLCs

- Safety impact: 4 (turbine overspeed possible)
- Operational impact: 5 (shutdown capability)
- Likelihood: 5 (no authentication, network-accessible)
- Business impact: 5 (major disruption risk)
- Remediation feasibility: 4 (firewall rules relatively easy)

Risk score: (4×2) + (5×1.5) + (5×1.5) + (5×1) = 8 + 7.5 + 7.5 + 5 = 28

Priority score: 28 / 4 = 7.0 (HIGH PRIORITY)

Finding: Anonymous access to OPC UA SCADA server

- Safety impact: 2 (no direct safety control)
- Operational impact: 2 (read-only access, no disruption)
- Likelihood: 5 (anonymous access enabled)
- Business impact: 3 (operational data disclosed)
- Remediation feasibility: 5 (enable authentication in config)

Risk score: (2×2) + (2×1.5) + (5×1.5) + (3×1) = 4 + 3 + 7.5 + 3 = 17.5

Priority score: 17.5 / 5 = 3.5 (MEDIUM PRIORITY)

Finding: Network segmentation absent

- Safety impact: 5 (lateral movement to safety systems)
- Operational impact: 5 (complete attack surface)
- Likelihood: 4 (foundational issue enabling other attacks)
- Business impact: 5 (systemic vulnerability)
- Remediation feasibility: 1 (major project, high cost, long timeline)

Risk score: (5×2) + (5×1.5) + (4×1.5) + (5×1) = 10 + 7.5 + 6 + 5 = 28.5

Priority score: 28.5 / 1 = 28.5 (HIGHEST PRIORITY - but long-term project)

### Interpretation

High priority scores (>10): Immediate attention, high risk and/or easy fix

Medium priority scores (5-10): Important but require planning or have lower risk

Low priority scores (<5): Address as resources permit, or accept risk

Special cases:

- High risk + low feasibility (e.g., segmentation): Start immediately even though completion is far out
- Low risk + high feasibility: Quick wins for demonstrating progress
- High safety impact: Override other factors (safety always wins)

### Facilitator role in prioritization workshop

Inject realism:

"Operations: How many hours of downtime do you have in your next maintenance window?"
"Blue team: What's your annual security budget? How much have you spent?"
"CISO: The Patrician wants monthly progress updates. What do you show him in month 1?"

Force trade-offs:

"You have 16 hours of maintenance window and €8,000 budget. Choose 3 quick wins. Not 4. Three."

Challenge assumptions:

"You rated that as easy to remediate. Operations, do you agree?"
"You said likelihood is high. Blue team, have you seen evidence of actual attacks?"

Build consensus:

"Red team says critical. Operations says we can't do it. How do we resolve this?"

## Phase 3: Implementation planning

Final phase: Turn prioritized findings into actionable project plans.

### Implementation plan template

For each Tier 1 recommendation (others get high-level plans):

Recommendation: [Specific fix]

Objective: [What this achieves]

Owner: [Person/team responsible]

Timeline:
- Planning: [dates]
- Implementation: [dates]
- Testing: [dates]
- Deployment: [dates]

Prerequisites:
- [What must be done first]
- [What must be available]

Resources required:
- Personnel: [who and how many hours]
- Budget: [itemized costs]
- Downtime: [how much and when]
- External support: [vendors, consultants]

Implementation steps:
1. [Specific action]
2. [Specific action]
3. [...]

Testing plan:
- [How to verify it works]
- [How to verify it doesn't break anything]
- [Rollback procedure if issues]

Success criteria:
- [Measurable outcomes]

Risks and mitigations:
- Risk: [What could go wrong]
  Mitigation: [How to prevent or respond]

Communication plan:
- Who needs to be notified
- What approval is required
- Documentation updates needed

### Example implementation plan

Recommendation: Deploy jump host for all administrative OT access

Objective:
- Centralize access control to OT systems
- Enable monitoring and auditing of administrative actions
- Eliminate direct network access to control systems from workstations

Owner: Blue team lead (with Operations approval)

Timeline:
- Planning: Weeks 1-2 (requirements, design, procurement)
- Implementation: Weeks 3-4 (install, configure, test)
- Training: Week 5 (operations and engineering staff)
- Deployment: Week 6 (cutover during maintenance window)

Prerequisites:
- Network segment identified for jump host placement
- Approved list of users requiring OT administrative access
- Firewall rules documented showing current access paths
- Backup authentication method for jump host failure scenario

Resources required:
- Personnel:
  - Blue team: 40 hours (setup and configuration)
  - Operations: 16 hours (testing and procedures)
  - Training: 8 hours (staff onboarding)
- Budget:
  - Hardware: €5,000 (hardened server)
  - Software: €8,000 (privileged access management solution)
  - Contingency: €2,000
  - Total: €15,000
- Downtime: 4 hours during maintenance window (firewall changes, testing)
- External support: Vendor support for PAM software (included in license)

Implementation steps:

1. Week 1: Design and procurement
   - Document current administrative access patterns
   - Design jump host architecture (placement, authentication, access controls)
   - Select PAM solution (evaluate 3 options)
   - Procure hardware and software
   - Develop access policy and procedures

2. Week 2: Build and configure
   - Install and harden jump host OS
   - Configure PAM software
   - Set up authentication (AD integration + MFA)
   - Configure access to target OT systems
   - Document configuration

3. Week 3: Testing phase 1 (lab)
   - Verify authentication mechanisms
   - Test access to each OT system type
   - Verify logging and auditing
   - Load testing (multiple simultaneous sessions)
   - Penetration testing of jump host itself

4. Week 4: Testing phase 2 (production read-only)
   - Grant test users access
   - Parallel operation (jump host available, direct access still works)
   - Validate functionality for each administrative use case
   - Identify and fix issues
   - Operator feedback and refinement

5. Week 5: Training and documentation
   - Train operations staff (4 hours)
   - Train engineering staff (4 hours)
   - Update documentation (access procedures, troubleshooting)
   - Create quick reference guides
   - Establish support process

6. Week 6: Cutover
   - During maintenance window:
     - Implement firewall rules removing direct access
     - Force all access through jump host
     - Verify each system accessible via jump host
     - Test emergency access procedure
     - Rollback plan ready if issues
   - Post-cutover monitoring (24/7 on-call for first week)

Testing plan:

*Functional testing:*
- Each administrative use case (PLC programming, SCADA configuration, network diagnostics)
- Multiple simultaneous users
- Different privilege levels
- Emergency access scenario
- Failure scenarios (jump host unavailable)

*Security testing:*
- Authentication bypass attempts
- Lateral movement from jump host
- Log tampering attempts
- Penetration test of jump host itself

*Operational testing:*
- Operations staff performing routine tasks
- Emergency response scenario
- Vendor support scenario
- Performance under load

*Rollback procedure:*
If critical issues during cutover:
1. Revert firewall rules (restore direct access)
2. Notify all users of temporary direct access
3. Document issue for resolution
4. Schedule new cutover after fix

Success criteria:
- 100% of administrative access via jump host (measured by firewall logs)
- Zero unplanned downtime caused by jump host
- 100% of administrative actions logged and auditable
- Operations staff trained and comfortable with new process
- Average connection time <30 seconds

Risks and mitigations:

*Risk: Jump host becomes single point of failure*
Mitigation:
- Break-glass emergency access procedure (documented, audited)
- High-availability configuration in future phase
- 24/7 monitoring of jump host availability

*Risk: Performance issues affect operations*
Mitigation:
- Load testing during implementation
- Parallel operation phase to identify issues
- Hardware sized for 10x expected load

*Risk: Users resist change, circumvent controls*
Mitigation:
- Involve operations in design phase
- Address usability concerns proactively
- Training emphasizes benefits (auditing protects them too)
- Enforce through firewall rules (circumvention not possible)

*Risk: Jump host compromise gives access to all OT systems*
Mitigation:
- Hardened OS with minimal attack surface
- Regular patching (monthly)
- Intrusion detection on jump host
- Privileged access management with session recording
- Regular security assessments of jump host

Communication plan:

*Before implementation:*
- Email to all affected users (week 1)
- Town hall presentation explaining change (week 2)
- Individual notification 1 week before cutover

*During implementation:*
- Daily status updates during parallel operation
- Change control board approval before cutover
- Notification 24 hours before cutover

*After implementation:*
- Success announcement
- Feedback collection
- Monthly metrics reporting (access patterns, incidents)

*Approvals required:*
- Operations Director: Design approval (week 1)
- CISO: Security architecture approval (week 2)
- Change Control Board: Cutover approval (week 5)

*Documentation updates:*
- Network architecture diagrams
- Access procedures (all OT systems)
- Emergency response procedures
- Onboarding documentation for new staff

---

### Facilitator guidance for implementation planning

During this session, teams work in breakouts:
- Red team + Blue team: Technical implementation details
- Operations team: Operational procedures and constraints
- Leadership: Budget and timeline approval

Facilitator circulates and injects reality:

"Have you considered what happens if the jump host fails during an emergency?"

"Your timeline shows 6 weeks. Operations has a maintenance window in 4 weeks. Next one is in 6 months. What do you do?"

"Budget shows €15,000. Bursar approved €8,000 for all quick wins. Negotiate."

Force teams to reconcile:

Bring teams back together periodically:
- Blue team presents plan
- Operations identifies concerns
- Leadership questions budget
- Teams negotiate and revise

Goal: Realistic implementation plans that all stakeholders can support.

---

## Remediation workshop outputs

By end of afternoon session, teams should have:

### 1. Complete penetration test report
- Executive summary
- Technical findings (10-15 minimum)
- Evidence for each finding
- Remediation recommendations

### 2. Prioritized remediation backlog
- All findings scored using matrix
- Findings organized into 3 tiers
- Justification for prioritization
- Risk reduction estimates

### 3. Detailed implementation plans (Tier 1 only)
- 3-5 quick wins with full plans
- Resource requirements
- Timeline with milestones
- Testing and rollback procedures

### 4. High-level roadmap (Tier 2 & 3)
- Strategic initiatives identified
- Rough timeline (quarters)
- Budget estimates
- Dependencies and prerequisites

### 5. Presentation materials
- Technical briefing slides
- Executive briefing slides
- Patrician briefing with strategic framing

These outputs are used in evening stakeholder presentations.

---

## Why this emphasis on remediation

Most security training stops at "find vulnerabilities, write report."

Real security work is:
- 20% finding problems
- 80% getting them fixed

The 80% requires:
- Understanding business context
- Prioritizing realistically
- Planning practically
- Communicating effectively
- Negotiating compromises
- Following through to completion

This simulation teaches the 80%.

Because pentesters who can't drive remediation are expensive report generators. Pentesters who can drive remediation are force multipliers for organizational security.

The UU P&L simulation, with its emphasis on remediation, produces the latter.

---

*"It's not what you find. It's what you do about what you find." - Ponder Stibbons (probably)*

*This is Ponder's lesson. She finds vulnerabilities efficiently, but her real skill is getting organizations to fix them. That's what this simulation teaches.*
