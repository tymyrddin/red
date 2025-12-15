# Prioritising remediation

*Because you can't fix everything at once, and some things are more "on fire" than others.*

[The pentest report](pentest-report.md) for UU P&L identified 159 findings. Twenty-three were rated critical or high. 
Forty-seven were medium. Eighty-nine were low. The engineering team consisted of five people, one of whom was six 
months from retirement and mainly concerned with not changing anything that might create problems for his successor. 
The available budget was €250,000, which sounds generous until you realise that complete network segmentation alone 
was estimated at €150,000.

This is the reality of OT remediation. You have more problems than resources, more recommendations than budget, 
and more urgent issues than available maintenance windows. The art is not in identifying everything that's wrong, 
that's easy. The art is in identifying what to fix first, what to fix eventually, and what to accept as residual 
risk while you work on the important things.

Prioritisation in OT is different from IT because the consequences are different. In IT, you prioritise based on 
likelihood and impact to data confidentiality, integrity, and availability. In OT, you prioritise based on safety risk, 
operational impact, and feasibility of implementation. A critical vulnerability in a safety system that can be fixed 
with a configuration change comes before a high vulnerability in a process control system that requires a complete 
network redesign.

## The risk matrix

The traditional risk matrix multiplies likelihood by impact to get a risk score. This works reasonably well in IT 
where both likelihood and impact are somewhat quantifiable. It works less well in OT where likelihood is often 
"we have no idea" and impact ranges from "minor inconvenience" to "people die."

At UU P&L, we adapted the risk matrix to reflect OT realities:

- Safety impact. Could this vulnerability, if exploited, result in injury or death? This trumps everything else. A vulnerability that allows bypassing safety systems is critical even if exploitation is difficult. A vulnerability that allows reading process data is low even if exploitation is trivial. Safety comes first, always.
- Operational impact. Could this vulnerability, if exploited, shut down production, damage equipment, or significantly disrupt operations? This is your second priority. A power generation facility that can't generate power is failing at its primary purpose, even if nobody gets hurt.
- Business impact. Could this vulnerability, if exploited, result in regulatory fines, reputational damage, or data exfiltration? This matters, but it matters less than safety and operations. The Archchancellor cares about the university's reputation, but he cares more about not having turbines explode.
- Likelihood. How likely is exploitation? This is where it gets messy. In theory, you assess likelihood based on attacker capability, system exposure, and existing controls. In practice, you're often guessing. A vulnerability on an internet-facing system is high likelihood. A vulnerability on an air-gapped network that requires physical access is low likelihood. Everything in between is judgment and experience.
- Ease of remediation. This is the factor that traditional risk matrices often ignore but that becomes crucial in OT. A critical finding that can be fixed with a configuration change should be addressed before a high finding that requires replacing equipment. Quick wins build momentum and demonstrate progress while you work on the long-term projects.

For UU P&L, we created a spreadsheet, because everything important eventually becomes a spreadsheet, with each finding rated across these dimensions. The critical findings fell into three categories:

- Critical-urgent: Safety impact, operationally feasible to fix quickly. "Change default passwords on PLCs accessible from IT network" is critical (allows unauthorised control) and urgent (can be done in a maintenance window). Fix immediately.
- Critical-complex: Safety impact, requires significant project work. "Implement hardware-enforced safety controls separate from process control network" is critical but requires equipment purchase, installation, and testing. Start the project now, complete it in six months.
- Critical-accepted: Safety impact, not currently feasible to remediate. "Replace legacy PLCs with models supporting encrypted protocols" is critical but costs €2 million and requires full shutdown. Document as residual risk, implement compensating controls, revisit in three years during planned equipment upgrade.

This is the uncomfortable reality of OT security. Some critical findings don't get fixed, at least not immediately. The safety risk is acknowledged, documented, and managed through compensating controls rather than eliminated. This is not ideal, but it is realistic.

## Quick wins and low-hanging fruit

Quick wins are important for several reasons. They demonstrate progress, build confidence that security improvements don't always mean massive disruption, and reduce risk while you work on the big projects. They're also usually inexpensive, which helps when you're justifying larger budget requests later.

At UU P&L, the quick wins included:

- Password changes (2 days, €0). Every system with default or weak passwords got new passwords following a proper policy. This included PLCs, HMIs, network devices, and engineering workstations. One person with a spreadsheet and a ladder (some PLCs required physical console access because remote access had been disabled, which was actually good security practice even if it made password changes inconvenient).
- Service hardening (1 week, €0). HMI workstations were running unnecessary services including web servers (why?), FTP servers (definitely why?), and in one case a Minecraft server (the intern's explanation of "testing" was not convincing). Disabling unnecessary services reduced attack surface and improved system performance.
- Basic network monitoring (2 weeks, €5,000). Deploying a passive network monitor on the OT network provided visibility into what systems existed, what they were communicating with, and whether any unusual traffic was occurring. This didn't prevent attacks but it meant attacks would be detected rather than successful unnoticed.
- Documented procedures (1 week, €0). Writing down "how to respond if we detect unauthorised PLC access" turned out to be valuable both for security and operational clarity. The previous procedure was apparently "panic and call everyone" which, while emotionally satisfying, was not particularly effective.
- Application whitelisting on HMIs (2 weeks, €3,000). Preventing arbitrary code execution on HMI systems significantly reduced ransomware risk. Implementation was surprisingly smooth once engineering accepted that no, they didn't need to install random utilities and browser toolbars on systems controlling turbines.

Quick wins totalled three months of effort (spread across the team, not consecutive) and €8,000. They addressed 15 findings, reduced the overall risk score by approximately 30%, and created momentum for the larger projects.

The danger of quick wins is stopping after the quick wins. It's very easy to fix the easy things, declare victory, and move on to other priorities. Quick wins should be the first step of a longer journey, not the entire journey.

## Compensating controls when patching isn't possible

In IT, the response to a vulnerability is usually "apply the patch." In OT, patches often don't exist, can't be applied without unacceptable downtime, or would void vendor support agreements. This is where compensating controls become essential.

A compensating control doesn't eliminate the vulnerability, it reduces the likelihood of exploitation or limits the impact if exploitation occurs. It's not as good as fixing the underlying problem, but it's significantly better than doing nothing.

At UU P&L, we identified several critical vulnerabilities that couldn't be directly patched:

**Turbine PLC firmware vulnerability** (CVE-2019-12345, allows remote code execution). The patch required a firmware upgrade that would void the support contract. The turbine vendor's official position was "upgrade to our new model" (€600,000 for three turbines, not in budget).

Compensating controls:
- Network segmentation preventing direct access to PLC network (reduces likelihood)
- Protocol firewall allowing only specific Modbus commands from authorised HMI (reduces exploit vectors)
- Enhanced monitoring detecting unusual PLC communications (reduces impact through early detection)
- Regular integrity checks of PLC program against known-good baseline (detects successful exploitation)
- Documented incident response procedures for suspected compromise (limits impact)

**Historian database authentication bypass** (allows complete access to historical data, no patch available for this EOL software). Upgrading to a supported version would require migrating ten years of historical data and rewriting multiple data analysis tools.

Compensating controls:
- Network segmentation isolating historian on dedicated VLAN (reduces likelihood)
- Read-only access from OT network, write access only from historian server itself (reduces impact)
- Enhanced logging of all database queries (detection)
- Regular backups stored offline (recovery)
- Data classification and access policies (limits sensitive data exposure)

**Legacy Windows XP HMI system** (no security updates since 2014, multiple critical vulnerabilities). Upgrading would require replacing the entire HMI software which is no longer supported and would require rewriting from scratch (€150,000, 12 months).

Compensating controls:
- Complete network isolation on dedicated VLAN with no internet access (significantly reduces likelihood)
- Application whitelisting allowing only essential HMI software (reduces exploit impact)
- USB port physical blocking (prevents local exploit delivery)
- Regular disk imaging allowing rapid restore (recovery)
- Parallel monitoring using modern system to reduce dependence (succession planning)

Compensating controls are documented risk acceptance. "We know this is vulnerable, we can't fix the root cause, here's what we're doing instead" needs to be written down, reviewed regularly, and included in risk registers. It's not a permanent solution but it is an honest acknowledgement of constraints and reasonable risk management.

## The roadmap

A security roadmap transforms the finding list into a project plan. It shows what will be fixed when, what resources are required, what dependencies exist, and what the expected outcome is. It's the difference between "we found 159 problems" and "here's how we'll address them over the next 18 months."

The UU P&L roadmap had five phases:

1. Quick wins and critical-urgent (0-3 months, €25,000). Password changes, service hardening, basic monitoring, and critical findings with simple fixes. Deliverable: immediate risk reduction and improved visibility.

2. Network segmentation (3-9 months, €150,000). Physical separation of IT and OT networks, firewall deployment, VLAN restructuring. This was the foundation for everything else. Deliverable: isolated OT network with controlled access points.

3. Enhanced security controls (9-15 months, €50,000). Protocol firewalls, application whitelisting, enhanced monitoring and alerting, secure remote access solution. These controls become effective once segmentation is complete. Deliverable: defence in depth.

4. Process improvements (12-18 months, €25,000). Incident response procedures, change management formalisation, security training, tabletop exercises. The technical controls are only effective if people know how to use them. Deliverable: sustainable security practices.

5. Strategic improvements (18-36 months, budget dependent). Equipment replacement planning for EOL systems, SIEM deployment, asset inventory and configuration management, industrial control system security audit program. These are the long-term improvements that fundamentally change the security posture. Deliverable: mature security program.

Each phase had defined milestones, responsible parties, and success criteria. "Network segmentation complete" meant specific technical deliverables: firewall rules documented and tested, network diagrams updated, all systems migrated to new architecture, verification testing passed. Not "we think we did it."

The roadmap included dependencies. Phase 3 couldn't start until Phase 2 was complete because protocol firewalls require segmented networks to be effective. Phase 4 should start during Phase 3 because training takes time and should be ongoing, not a final checkbox.

Importantly, the roadmap was realistic about timing. Nine months for network segmentation wasn't pessimistic, it was based on the realities of OT environments: coordination with operations to schedule downtime, procurement processes for equipment, vendor delivery times, installation and testing, and the inevitable problems that arise when you discover that the network documentation was last updated in 2015 and is mostly wrong.

## Budget justification

Security improvements require budget. Budget requires justification. "We need €250,000 because the pentest found problems" is not compelling justification. "We need €250,000 to address critical safety and operational risks" is better but still insufficient.

The budget justification for UU P&L included:

- Risk quantification. "The identified vulnerabilities create an estimated annual loss expectancy of €500,000 based on potential downtime (€200,000), equipment damage (€200,000), and regulatory fines (€100,000). The proposed €250,000 investment reduces this risk by approximately 80%." This is somewhat made-up mathematics, but it's made-up mathematics that executives understand.
- Regulatory compliance. "The current security posture does not meet the requirements of NIS2 Directive. Non-compliance could result in fines up to €10 million or 2% of annual revenue. The proposed improvements bring us into compliance." Regulators are remarkably effective at motivating budget allocation.
- Comparative analysis. "Industry benchmarking shows that peer organisations invest 3-5% of IT/OT budget on security. Our current investment is 0.5%. The proposed budget represents 2% of IT/OT budget, which is at the low end of industry standard but represents significant improvement." Being better than your past self while still worse than your peers is a comfortable middle ground.
- Incident prevention. "Recent ransomware attacks on similar facilities resulted in average downtime of 14 days and average costs of €2 million. The proposed security improvements significantly reduce ransomware risk through network segmentation, application whitelisting, and enhanced monitoring." Real incidents at other organisations are very motivating.
- Insurance considerations. "Our cyber insurance policy requires reasonable security measures. The insurer has indicated that the current posture may not meet policy requirements, potentially voiding coverage. The proposed improvements ensure continued coverage." Insurance companies are surprisingly helpful in justifying security spending.

The budget request was approved with only minor reductions (€225,000 instead of €250,000, some strategic improvements deferred). The key was framing it not as "spending money on security" but as "spending money to prevent much larger costs."

## Measuring progress

Security roadmaps are long-term commitments. Measuring progress is essential both for maintaining momentum and demonstrating value.

At UU P&L, we established metrics:

- Findings remediated. Simple count. "We've closed 45 of 159 findings (28%)" shows clear progress. Break this down by severity: "We've closed 15 of 23 critical/high findings (65%)" is more compelling.
- Risk score reduction. Quantify the aggregate risk. "We've reduced the overall risk score from 8.5 (critical) to 4.2 (medium)" gives a single number for executives who like single numbers.
- Milestones achieved. "Network segmentation Phase 2 complete on schedule" demonstrates project management effectiveness and builds confidence in the roadmap.
- Time to detection. "We've reduced time to detect unauthorised PLC access from 'never' to 15 minutes" shows the value of monitoring investments.
- Incident rate. "Zero successful attacks against OT systems in the six months since security improvements" is the ultimate metric, though also the hardest to verify (absence of detected incidents could mean absence of incidents or absence of detection capability).

Quarterly reviews compared actual progress against the roadmap, identified obstacles and delays, adjusted priorities based on new information, and communicated status to leadership. This regular cadence kept security on the agenda rather than forgotten until the next crisis.

Eighteen months after the initial assessment, UU P&L had completed Phases 1-3, partially completed Phase 4, and was planning Phase 5. The critical and high findings were all remediated or had documented compensating controls. The medium findings were 60% complete. The low findings were mostly deferred because, honestly, low findings are low for a reason.

More importantly, security had moved from "thing we should probably think about" to "ongoing operational practice." New systems were evaluated for security implications. Change management included security reviews. Engineering staff attended security training and actually retained some of it. The OT security posture had fundamentally improved.

This is what successful prioritisation and remediation looks like. Not perfection, but meaningful improvement. Not elimination of all risk, but systematic reduction of the most significant risks. Not security theatre, but practical security engineering informed by operational realities.

Start with the quick wins, address the critical findings, build the foundation for long-term improvements, and measure your progress. Everything else is just hoping things work out, and hope is not a strategy.
