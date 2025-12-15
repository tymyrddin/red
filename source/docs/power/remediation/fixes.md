# Implementing fixes

*Turning recommendations into reality without breaking production.*

The pentest report is written. The roadmap is approved. The budget is allocated. Now comes the hard part: actually implementing security improvements in a production OT environment where downtime costs €10,000 per hour, changes require six weeks of planning, and any mistake could result in the university chancellor receiving angry phone calls from the city about why the street lights aren't working.

Implementation in OT is fundamentally different from IT. In IT, you can test changes in a development environment, deploy to a staging environment, and roll out to production with reasonable confidence. In OT, you often don't have a development environment (too expensive) or a staging environment (no space), and rolling back a failed change might require physically rewiring equipment while production is offline.

At UU P&L, implementing the security roadmap required eighteen months of careful coordination, several near-disasters that were caught just in time, one actual incident that taught valuable lessons, and persistent attention to the reality that we were modifying systems that kept the lights on for 50,000 people who mostly didn't care about security but very much cared about reliable electricity.

## Change management in OT

Change management in IT is often bureaucratic overhead. Change management in OT is operational necessity. The difference is that failed changes in IT might break email for a few hours. Failed changes in OT might shut down production or create safety hazards.

The UU P&L change management process, which existed in theory before our assessment but was mostly honoured in the breach, was formalized into something actually effective:

- Change request documentation. Every change required a formal request including: what's changing, why it's changing, what systems are affected, what testing has been done, what the rollback plan is, what downtime is required, and who's responsible. The request template was two pages, which seems bureaucratic until you realise that thinking through these questions before making changes prevents problems.
- Risk assessment. Every change was assessed for operational risk (could this break production?), safety risk (could this create hazards?), and security risk (could this create new vulnerabilities?). Changes were categorized as low, medium, or high risk with different approval requirements.
- Testing requirements. Low-risk changes (password changes, configuration backups) required verification testing. Medium-risk changes (firewall rule modifications, VLAN changes) required testing in isolated environment where possible and detailed verification in production. High-risk changes (network segmentation, major system updates) required formal test plans with acceptance criteria.
- Approval workflow. Low-risk changes required OT engineer approval. Medium-risk changes required senior engineer and operations manager approval. High-risk changes required engineering, operations, and management approval plus coordination with the university's facility management office who needed to notify people about potential disruptions.
- Maintenance windows. Routine changes happened during scheduled maintenance windows (first Sunday of each month, 06:00-14:00). Emergency changes followed an expedited process but still required documentation and approval. The definition of "emergency" was refined after someone tried to use the emergency process to implement a non-urgent network change on a Tuesday afternoon, which did not go well.
- Change log and audit trail. Every change was documented with before/after configurations, verification test results, and any issues encountered. This created institutional knowledge and made troubleshooting easier when problems appeared weeks later.

The formalised change management added overhead, approximately two hours of paperwork for a typical change. It also prevented three potentially serious incidents in the first six months alone, including one proposed firewall change that would have blocked critical SCADA traffic and one VLAN modification that would have isolated the HMI systems from the PLCs they controlled.

Change management is not exciting. It is, however, effective.

## Patch testing procedures

Patching in OT is fraught with danger. Patches designed for IT systems often have unexpected effects on OT systems. Vendor patches sometimes break things. And patches can't usually be uninstalled, which means a bad patch might require complete system reinstallation.

At UU P&L, we established a patch testing procedure:

- Patch evaluation. Before testing any patch, we evaluated: what does this patch fix, what systems does it affect, what are the known compatibility issues, what do other OT facilities report about this patch? This evaluation often revealed that a patch wasn't actually relevant (fixing a vulnerability in a service we don't use) or was known to cause problems (widespread reports of HMI crashes after installation).
- Test environment patching. Where test environments existed (mostly HMI workstations and some network equipment), patches were installed and verified. Test environments were configured to match production as closely as possible, including hardware, software versions, network configuration, and connected devices. The limitation was that test environments often used older spare equipment, which sometimes meant compatibility issues only appeared in production.
- Isolated production testing. For systems without test environments (most PLCs, some SCADA servers), we identified an isolated production system for initial testing. The third turbine was usually offline during low-demand periods and could be used for testing without risking the primary generation units. This wasn't a true test environment but it was better than patching everything simultaneously.
- Verification testing. After patch installation, verification included: system boots successfully, all services start correctly, HMI connects to PLCs, SCADA can read sensor data, historical trending works, alarm systems function, backup and restore procedures work. Verification was documented with screenshots and test results.
- Staged rollout. Patches were rolled out progressively: test environment, isolated production system, one production system, all production systems. If problems appeared at any stage, rollout stopped until issues were resolved. This made patching slower but significantly safer.
- Rollback planning. Every patch had a documented rollback procedure. For Windows systems this meant system images before patching. For network devices this meant configuration backups. For PLCs this meant program backups and documented rollback procedures (which sometimes meant "call the vendor and pray").

The patch testing process added approximately two weeks to the time between "patch released" and "patch deployed to all systems." This seems slow compared to IT environments where patches might be deployed within days. It's appropriately cautious for OT environments where failed patches might shut down power generation.

We discovered this the hard way when a Windows update for HMI workstations, which passed all testing, inexplicably caused the HMI software to crash every two hours in production. The problem only appeared under sustained load and specific timing conditions that weren't replicated in testing. The rollback procedure worked perfectly and the systems were restored in 30 minutes. The incident report was six pages. The new verification testing requirements were expanded to include 48-hour sustained load testing for HMI patches.

## Configuration changes

Most security improvements in OT don't involve patches, they involve configuration changes: firewall rules, network segmentation, access controls, monitoring configurations. These changes are often reversible, which makes them less risky than patches, but they can still break things in creative ways.

At UU P&L, the major configuration change project was network segmentation:

1. Documentation and planning (6 weeks). Document every network connection, identify what needs to communicate with what, design the new network architecture, create VLAN structure, define firewall rules, plan migration sequence. This was tedious but essential. We discovered seventeen undocumented network connections including one mysterious system that nobody could identify but that turned out to be critical for the cooling system monitoring.

2. Preparation (4 weeks). Procure and install new network equipment, configure VLANs and firewalls in preparation mode (monitoring only, not enforcing), deploy monitoring to verify understanding of traffic patterns. The monitoring revealed that our documentation was approximately 80% accurate and that the remaining 20% included several critical connections we hadn't identified.

3. Staged migration (12 weeks). Migrate systems to new network architecture one subnet at a time. Start with the least critical systems (office network), proceed to more critical systems (monitoring network), complete with most critical systems (control network). Each migration included verification testing and a 48-hour monitoring period before proceeding to the next stage.

4. Firewall enforcement (2 weeks). Once all systems were migrated and verified, enable firewall enforcement. This was done progressively: block obviously unnecessary traffic first, add specific allow rules for required traffic, monitor for broken functionality. The goal was zero blocked legitimate traffic, which we achieved after approximately two weeks of rule refinement.

5. Verification and documentation (2 weeks). Comprehensive testing of all functionality, documentation updates, training for operations staff, procedure documentation. The network diagrams were updated to reflect reality, which made them useful for the first time in years.

Total timeline: six months. Total downtime: 16 hours spread across three maintenance windows. Total unexpected issues: 23, mostly minor but including three that required urgent fixes.

The most significant issue appeared three weeks after migration completion. The university library's HVAC system, which was on the office network, had an undocumented connection to the power monitoring system for backup power coordination. The network segmentation broke this connection. The immediate symptom was that the library HVAC failed to switch to backup power during a test. The underlying problem was that nobody had documented this connection because it had been implemented years ago by a contractor who was now retired and nobody thought to mention it during our requirements gathering.

The fix was straightforward once we understood the problem: allow specific traffic between the office and monitoring networks for this purpose. The lesson was that documentation is never complete and testing must be thorough and sustained.

## Network segmentation projects

Network segmentation is one of the most effective security controls for OT and also one of the most disruptive to implement. Getting it right requires understanding not just the network architecture but the operational dependencies that the network supports.

At UU P&L, the segmentation project divided the network into five zones:

- Corporate IT network. General office systems, email, business applications. Standard IT security: patched regularly, antivirus, user authentication, internet access. This network had no business talking to industrial controls.
- Engineering network. Engineering workstations, design tools, documentation. Requires access to OT for engineering purposes but shouldn't allow direct control. Implemented as a DMZ with controlled access to both IT and OT.
- Operations network. HMI systems, SCADA servers, data historians. Needs to communicate with control network but should be isolated from IT. Monitoring and visualisation but not direct control.
- Control network. PLCs, RTUs, field devices. The actual controllers. Should be accessible only from operations network and only via specific protocols. Most restrictive network.
- Safety network. Safety PLCs and safety-critical systems. Completely isolated from all other networks. Physical separation, no IP connectivity. This is not paranoia, this is IEC 61511.

The firewall rules between zones were based on the principle of minimum necessary access. The operations network could read from control network PLCs but writes required specific authorised HMI systems. The engineering network could connect to PLCs for programming but only during scheduled maintenance windows and with logging. The IT network couldn't see the OT networks at all except for specific monitored connections for backup and patch management.

Implementation was staged by zone with the safety network going first (already mostly isolated, just needed formalisation) and the control network going last (most critical, most testing required).

## Monitoring and detection deployment

Security controls are only effective if you know when they're being violated. Monitoring in OT serves multiple purposes: detecting security incidents, identifying operational anomalies, providing audit trails, and verifying that security controls are functioning.

At UU P&L, we deployed three layers of monitoring:

- Network monitoring. Passive taps on critical network segments capturing all traffic. The monitoring system learned normal traffic patterns, detected anomalies, and generated alerts for suspicious activity. This caught several interesting things in the first month including someone's personal laptop that had been connected to the OT network for file sharing (why?), a PLC that was beaconing to an internet address (turned out to be NTP, blocked by firewall, PLC had no idea), and several mobile devices on the engineering network that shouldn't have been there (engineers using their phones as WiFi hotspots, which was creative but inappropriate).
- Host-based monitoring. Logging and monitoring on critical systems (HMIs, SCADA servers, historians). This included Windows event logs, application logs, and security tool logs (application whitelisting, antivirus). Logs were forwarded to a central collection system for analysis and correlation. The log analysis revealed that one HMI was rebooting every three days, which turned out to be a memory leak in a data collection utility that nobody had noticed because the automatic reboot happened during low-activity periods.
- PLC monitoring. Regular integrity checks of PLC programs compared against known-good baselines. Any modifications triggered alerts for investigation. We also monitored PLC communications for unusual patterns (writes from unauthorised systems, excessive reads that might indicate reconnaissance, communications to unexpected destinations). This detected nothing malicious but caught several legitimate issues including a poorly written data collection script that was querying PLCs hundreds of times per second and affecting performance.

The monitoring generated approximately 50 alerts per day initially, most of which were false positives or low-priority informational alerts. Tuning the monitoring to reduce noise while maintaining sensitivity took three months. The final configuration generated 3-5 alerts per day that required investigation, which was manageable.

The monitoring also provided unexpected operational benefits. Detecting unusual network traffic sometimes identified equipment problems before they caused failures. Monitoring PLC program integrity caught accidental modifications and potentially prevented issues. Log analysis of HMI systems identified performance problems that were affecting operator efficiency.

## Training and awareness

Technical controls are necessary but insufficient. People operate the systems, respond to alerts, and make decisions about security. If the people don't understand security, the technical controls are much less effective.

At UU P&L, security training included:

- General security awareness (annual, all staff). Basic security principles, phishing recognition, password security, physical security, incident reporting. This was the standard corporate training that everyone receives and mostly ignores, but compliance is compliance.
- OT security fundamentals (initial training, all OT staff). Why OT security is different from IT security, what the threats are, what the security controls do, how to recognise suspicious activity, what to do if something seems wrong. This was actually useful and generally well-received.
- Specific system training (as needed, relevant staff). How to use the new monitoring system, how to interpret alerts, how to investigate potential incidents, how to use the secure remote access system, how to follow change management procedures. This was hands-on practical training that people actually needed.
- Tabletop exercises (quarterly, OT leadership and key staff). Scenario-based discussion of "what would we do if...?" covering various incident scenarios. These exercises identified gaps in procedures, unclear responsibilities, and communication issues. They also built relationships between IT, OT, and management which proved valuable when real incidents occurred.

The most valuable training outcome was cultural change. Security stopped being "that thing IT worries about" and became "part of how we operate systems safely." Engineers started thinking about security implications of changes. Operators reported suspicious activity instead of ignoring it. Management understood why security investments were necessary.

This cultural change didn't happen because of training alone, it happened because training was combined with effective security controls, visible leadership support, and regular reinforcement. But training was the foundation.

## The inevitable incident

Despite all the planning, testing, and careful implementation, incidents happen. At UU P&L, six months into the security roadmap, we had our first major security incident.

A contractor working on HVAC upgrades brought a laptop onto site. The laptop was infected with malware, probably picked up from a previous job. The contractor connected the laptop to the university network to download updated equipment specifications. The malware, which was primarily designed for data exfiltration and ransomware delivery, began spreading laterally.

The network segmentation stopped the malware from reaching the OT networks. The monitoring detected unusual network traffic and generated alerts. The incident response procedures were followed. The infected systems were isolated, cleaned, and restored. The contractor's laptop was quarantined and his network access was revoked. Total impact: two office workstations and one engineering workstation compromised, contained within 45 minutes, no operational disruption, no data exfiltration.

This was simultaneously a successful demonstration of the security improvements and a reminder that security is never perfect. The malware got in because contractor security procedures were inadequate. The damage was limited because the segmentation worked. The incident was detected quickly because the monitoring worked. The response was effective because procedures existed and people knew how to follow them.

The incident report was presented to university leadership. The headline was not "we had an incident" but "our security improvements worked." This reinforced the value of the security investments and ensured continued support for the remaining roadmap items.

The incident also identified areas for improvement: contractor security requirements needed to be more explicit and verified, monitoring could be tuned to detect this type of malware spread faster, and incident response procedures needed minor refinements based on lessons learned.

## Lessons from implementation

Eighteen months after starting the security roadmap, UU P&L had implemented network segmentation, deployed monitoring and detection capabilities, formalised change management, improved patch procedures, trained staff, and built a sustainable security program.

The lessons learned:

- Take time for planning. The six weeks spent documenting the network before segmentation was essential. Incomplete documentation would have resulted in broken systems and emergency fixes.
- Test everything. The patch that worked fine in testing but crashed production HMI systems demonstrated that testing needs to be comprehensive and realistic. Testing finds problems when they're easy to fix.
- Start with quick wins. The password changes and service hardening that took days to implement built momentum and confidence for the larger projects. Quick wins demonstrate that security doesn't always mean massive disruption.
- Accept imperfection. Not every vulnerability can be fixed. Not every recommendation can be implemented immediately. Document what you can't fix, implement compensating controls, and move forward with what you can fix.
- Communicate constantly. Regular updates to leadership, coordination with operations, and engagement with engineering kept security on the agenda and ensured support when problems appeared.
- Learn from incidents. The contractor laptop incident taught valuable lessons and actually strengthened the security program by demonstrating its effectiveness.
- Maintain momentum. Security roadmaps are long-term commitments. Quarterly reviews, visible progress, and regular communication prevent security from being forgotten after the initial enthusiasm fades.

Implementation is where security recommendations either succeed or fail. Success requires technical competence, operational understanding, persistence, and the willingness to adapt when things don't go according to plan. It requires accepting that perfection is impossible and that meaningful improvement is sufficient.

The UU P&L security posture isn't perfect. The turbine PLCs still run vulnerable firmware because replacement isn't feasible. Some legacy systems remain because they still work and replacement would be expensive. The documentation is approximately 95% accurate because the other 5% keeps changing.

But the security posture is significantly better than it was. The critical vulnerabilities are addressed. The network is segmented. The monitoring detects problems. The procedures are documented. The culture has changed from "security is IT's problem" to "security is how we protect operational systems."

This is what successful implementation looks like in OT security. Not perfection, but meaningful improvement. Not elimination of all risk, but systematic reduction of the most significant risks through technical controls, procedural improvements, and cultural change.

Start with the foundation, build in layers, test thoroughly, communicate constantly, and accept that some problems will take years to fully resolve. Everything else is either impossible or inadvisable, and distinguishing between the two is the art of OT security implementation.
