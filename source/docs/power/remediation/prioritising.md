# Prioritising remediation: Because you can't fix everything at once

*Or: How Ponder Learnt That Technical Severity Isn't The Only Thing That Matters*

## The problem of finite resources

The UU P&L simulator assessment identifies 159 findings. Twenty-three are rated critical or high. Forty-seven are medium. Eighty-nine are low. All of these are technically accurate assessments of protocol-level vulnerabilities.

What the simulator doesn't tell you is:
- Which ones matter most in your specific operational context
- Which ones are actually fixable with available resources
- Which ones will require six months of planning and €150,000
- Which ones can be fixed in an afternoon with zero cost

This is the reality of OT remediation. You have more problems than resources, more recommendations than budget, and more urgent issues than available maintenance windows. The art is not in identifying everything that's wrong (the simulator makes that straightforward). The art is in identifying what to fix first, what to fix eventually, and what to accept as residual risk whilst you work on the important things.

Prioritisation in OT is different from IT because the consequences are different. In IT, you prioritise based on likelihood and impact to data confidentiality, integrity, and availability. In OT, you prioritise based on safety risk, operational impact, and feasibility of implementation.

## What the simulator teaches about prioritisation

The simulator helps calibrate technical severity:

### Protocol-level vulnerability severity

Critical findings:
- Unauthenticated write access to safety PLC
- Ability to bypass safety interlocks
- Direct manipulation of safety-critical systems

High findings:
- Unauthenticated write access to production PLCs
- Ability to manipulate process parameters
- Potential for equipment damage or operational disruption

Medium findings:
- Read-only access to sensitive data
- Reconnaissance capabilities
- Intellectual property exposure

Low findings:
- Information disclosure of non-sensitive data
- Minor configuration issues
- Violations of security best practises without direct impact

The simulator demonstrates these severity levels through actual exploitation:

[Turbine overspeed attack](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation/turbine_overspeed_attack.py) demonstrates high-severity finding (equipment damage risk)

[Emergency stop attack](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation/turbine_emergency_stop.py) demonstrates high-severity finding (operational disruption)

[S7 memory reading](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/vulns/s7_read_memory.py) demonstrates medium-severity finding (intellectual property theft)

[Anonymous OPC UA browsing](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/opcua_readonly_probe.py) demonstrates medium-severity finding (reconnaissance enablement)

### Technical risk understanding

The simulator teaches what attacks look like and what they can achieve. This helps calibrate technical risk:

Understanding impact:
- What can actually be done with Modbus write access?
- How dangerous is S7 memory reading?
- What does anonymous OPC UA enable?
- How much can be accomplished with read-only access?

Understanding exploit difficulty:
- How easy is protocol exploitation?
- What skill level is required?
- What tools are needed?
- How quickly can attacks be executed?

Understanding detection likelihood:
- Would this attack be detected?
- How obvious is exploitation?
- Can it be done stealthily?
- What monitoring would catch it?

This technical understanding is essential for prioritisation, but it's not sufficient.

## What the simulator doesn't teach

The simulator can't teach organisational factors that determine real prioritisation:

### Budget realities

Simulator perspective:
- Network segmentation prevents protocol attacks
- Therefore network segmentation is high priority

Production reality:
- Network segmentation costs €150,000
- Available budget is €225,000 total
- Must also address 22 other high-priority findings
- Network segmentation is 67% of budget for one finding

Budget constraints force prioritisation decisions the simulator can't anticipate.

### Operational constraints

Simulator perspective:
- PLC firmware vulnerability is critical
- Therefore PLC should be patched

Production reality:
- Patching requires 8-hour production shutdown
- Shutdown costs €10,000/hour in lost production
- Patch voids vendor support contract
- Vendor recommends "upgrade to new hardware" (€600,000)
- Patching isn't feasible

Operational constraints prevent fixes that are technically sound but practically impossible.

### Stakeholder priorities

Simulator perspective:
- Safety system vulnerability is critical
- Therefore fix immediately

Production reality:
- Safety engineer agrees it's important
- Operations manager concerned about downtime
- Finance worried about budget
- Vendor needs three months notice for support
- Implementation delayed pending coordination

Stakeholder alignment takes time and negotiation the simulator can't simulate.

## The risk matrix for OT environments

Traditional risk matrices multiply likelihood by impact. This works in IT where both are somewhat quantifiable. It works less well in OT where likelihood is often "we have no idea" and impact ranges from "minor inconvenience" to "people die."

Adapted risk matrix reflecting OT realities:

### Safety impact

Could this vulnerability, if exploited, result in injury or death?

This trumps everything else. Vulnerability allowing safety system bypass is critical even if exploitation is difficult. Vulnerability allowing process data reading is low even if exploitation is trivial.

Safety comes first, always.

### Operational impact

Could this vulnerability, if exploited, shut down production, damage equipment, or significantly disrupt operations?

This is second priority. Power generation facility that can't generate power is failing at its primary purpose, even if nobody gets hurt.

### Business impact

Could this vulnerability, if exploited, result in regulatory fines, reputational damage, or data exfiltration?

This matters, but it matters less than safety and operations. The Archchancellor cares about reputation, but cares more about not having turbines explode.

### Likelihood

How likely is exploitation?

In theory, assess likelihood based on attacker capability, system exposure, and existing controls. In practice, you're often guessing.

Vulnerability on internet-facing system: high likelihood
Vulnerability on air-gapped network requiring physical access: low likelihood
Everything in between: judgement and experience

### Ease of remediation

How difficult is this to fix?

This is the factor traditional risk matrices often ignore but that becomes crucial in OT. Critical finding that can be fixed with configuration change should be addressed before high finding that requires replacing equipment.

Quick wins build momentum and demonstrate progress whilst you work on long-term projects.

## Prioritisation categories

Based on simulator findings and real-world constraints, findings fall into categories:

### Critical-urgent

Characteristics:
- Safety impact
- Operationally feasible to fix quickly
- Available resources

Example from simulator:
"Change default passwords on PLCs accessible from IT network"
- Critical: allows unauthorised control
- Urgent: can be done in maintenance window
- Fix immediately

### Critical-complex

Characteristics:
- Safety impact
- Requires significant project work
- Multi-month timeline

Example from simulator:
"Implement network segmentation isolating safety systems"
- Critical: prevents safety system compromise
- Complex: requires equipment purchase, installation, testing
- Start project now, complete in six months

### Critical-accepted

Characteristics:
- Safety impact
- Not currently feasible to remediate
- Requires long-term planning

Example:
"Replace legacy PLCs with models supporting encrypted protocols"
- Critical: current PLCs lack security features
- Accepted: costs €2 million and requires full shutdown
- Document as residual risk, implement compensating controls, revisit during planned equipment upgrade

This is the uncomfortable reality of OT security. Some critical findings don't get fixed immediately. Safety risk is acknowledged, documented, and managed through compensating controls rather than eliminated.

## Quick wins from simulator findings

Quick wins demonstrate progress, build confidence, and reduce risk whilst working on big projects. They're also usually inexpensive.

Based on simulator testing, quick wins include:

### Password changes (2 days, €0)

Every system with default or weak passwords gets new passwords following proper policy. This addresses findings from:
- Modbus authentication testing
- S7 password probing
- OPC UA anonymous access

One person with spreadsheet and ladder (some PLCs require physical console access).

### Service hardening (1 week, €0)

HMI workstations running unnecessary services get them disabled. This reduces attack surface shown by reconnaissance scripts.

Findings addressed:
- Unnecessary network services exposed
- Attack surface unnecessarily large
- Multiple potential exploit vectors

### Basic network monitoring (2 weeks, €5,000)

Deploy passive network monitor on OT network providing visibility. This enables detection of attacks demonstrated in simulator.

Findings addressed:
- No detection capability
- Attacks go unnoticed
- No visibility into OT network traffic

### Documented procedures (1 week, €0)

Write down "how to respond if we detect unauthorised PLC access". Previous procedure was "panic and call everyone" which, whilst emotionally satisfying, was not particularly effective.

### Application whitelisting (2 weeks, €3,000)

Preventing arbitrary code execution on HMI systems significantly reduces ransomware risk. Implementation smooth once engineering accepts that no, they don't need random utilities on systems controlling turbines.

Quick wins total: Three months of effort, €8,000, addresses 15 findings, reduces overall risk score by approximately 30%.

Danger of quick wins is stopping after quick wins. They should be first step of longer journey, not entire journey.

## Compensating controls when patching isn't possible

The simulator demonstrates vulnerabilities. Real facilities often can't patch them. This is where compensating controls become essential.

Compensating control doesn't eliminate vulnerability. It reduces likelihood of exploitation or limits impact if exploitation occurs. Not as good as fixing underlying problem, but significantly better than doing nothing.

### Example: Turbine PLC firmware vulnerability

Simulator finding:
"Firmware version 3.2.1 vulnerable to CVE-2019-12345 allowing remote code execution"

Production constraint:
- Patch requires firmware upgrade voiding support contract
- Vendor's official position: "upgrade to new model" (€600,000, not in budget)

Compensating controls:
1. Network segmentation preventing direct access to PLC network (reduces likelihood)
2. Protocol firewall allowing only specific Modbus commands from authorised HMI (reduces exploit vectors)
3. Enhanced monitoring detecting unusual PLC communications (reduces impact through early detection)
4. Regular integrity checks of PLC programme against known-good baseline (detects successful exploitation)
5. Documented incident response procedures (limits impact)

### Example: Historian database authentication bypass

Simulator finding:
"OPC UA historian allows anonymous access to all historical data"

Production constraint:
- No patch available (end-of-life software)
- Upgrading requires migrating ten years of historical data
- Multiple data analysis tools would need rewriting
- Cost: €100,000, Timeline: 12 months

Compensating controls:
1. Network segmentation isolating historian on dedicated VLAN (reduces likelihood)
2. Read-only access from OT network (reduces impact)
3. Enhanced logging of all database queries (detection)
4. Regular backups stored offline (recovery)
5. Data classification and access policies (limits sensitive data exposure)

Compensating controls are documented risk acceptance. "We know this is vulnerable, we can't fix root cause, here's what we're doing instead" needs to be written down, reviewed regularly, and included in risk registers.

## The remediation roadmap

Security roadmap transforms finding list into project plan. It shows what will be fixed when, what resources are required, what dependencies exist, and expected outcome.

Based on simulator findings, example roadmap:

### Phase 1: Quick wins and critical-urgent (0-3 months, €25,000)

Deliverable: Immediate risk reduction and improved visibility

Activities:
- Password changes across all systems
- Service hardening on HMI workstations
- Basic network monitoring deployment
- Critical findings with simple fixes

### Phase 2: Network segmentation (3-9 months, €150,000)

Deliverable: Isolated OT network with controlled access points

Activities:
- Physical separation of IT and OT networks
- Firewall deployment
- VLAN restructuring
- Foundation for everything else

### Phase 3: Enhanced security controls (9-15 months, €50,000)

Deliverable: Defence in depth

Activities:
- Protocol firewalls
- Application whitelisting
- Enhanced monitoring and alerting
- Secure remote access solution

### Phase 4: Process improvements (12-18 months, €25,000)

Deliverable: Sustainable security practises

Activities:
- Incident response procedures
- Change management formalisation
- Security training
- Tabletop exercises

### Phase 5: Strategic improvements (18-36 months, budget dependent)

Deliverable: Mature security programme

Activities:
- Equipment replacement planning for end-of-life systems
- SIEM deployment
- Asset inventory and configuration management
- Industrial control system security audit programme

Each phase has defined milestones, responsible parties, and success criteria. Dependencies are documented. Phase 3 can't start until Phase 2 complete because protocol firewalls require segmented networks.

## Budget justification

Security improvements require budget. Budget requires justification beyond "simulator found problems."

Effective budget justification includes:

Risk quantification:
"Identified vulnerabilities create estimated annual loss expectancy of €500,000 based on potential downtime (€200,000), equipment damage (€200,000), and regulatory fines (€100,000). Proposed €250,000 investment reduces this risk by approximately 80%."

Regulatory compliance:
"Current security posture doesn't meet NIS2 Directive requirements. Non-compliance could result in fines up to €10 million or 2% of annual revenue. Proposed improvements bring us into compliance."

Comparative analysis:
"Industry benchmarking shows peer organisations invest 3-5% of IT/OT budget on security. Our current investment is 0.5%. Proposed budget represents 2% of IT/OT budget, at low end of industry standard but represents significant improvement."

Incident prevention:
"Recent ransomware attacks on similar facilities resulted in average downtime of 14 days and average costs of €2 million. Proposed security improvements significantly reduce ransomware risk."

Insurance considerations:
"Cyber insurance policy requires reasonable security measures. Insurer indicated current posture may not meet policy requirements, potentially voiding coverage. Proposed improvements ensure continued coverage."

## Ponder's perspective on prioritisation

Ponder's testing journal included notes about prioritisation:

"The simulator teaches me which vulnerabilities are technically severe. It doesn't teach me which ones I can actually fix with available budget, limited maintenance windows, and stakeholder concerns about downtime.

"Technical severity is necessary for prioritisation. It's not sufficient. Real prioritisation requires understanding operational constraints, budget realities, and organisational dynamics.

"The simulator shows that unauthenticated Modbus access is high severity. Production shows that fixing it requires €150,000 network segmentation project that takes six months and requires coordination with operations, finance, and management.

"Both types of knowledge matter. The simulator provides the first. Real facilities provide the second. Effective prioritisation requires both."

## Resources for prioritisation

The simulator teaches technical severity. These resources teach real-world prioritisation:

Risk frameworks:
- IEC 62443 risk assessment methodology
- OT-specific risk matrices
- Business impact assessment templates

Project planning:
- Remediation roadmap templates
- Resource allocation frameworks
- Dependency mapping tools

Budget justification:
- Cost-benefit analysis templates
- Risk quantification methodologies
- Industry benchmarking data

Use simulator to understand technical risk. Use production experience to understand organisational priorities. Both are essential for effective remediation prioritisation.

Further reading:
- [Implementing Fixes](fixes.md) - Turning recommendations into reality
- [Writing Reports](pentest-report.md) - Communicating findings effectively
- [Attack Walkthroughs](../exploitation/walkthroughs.md) - Understanding attack progressions

The simulator teaches what's vulnerable. Real facilities teach what's fixable. Both are essential for successful OT security improvement.
