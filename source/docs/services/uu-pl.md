# The UU Power & Light training programme

*Or: How Ponder's Experience Became A Teaching Curriculum*

## Workshop overview

The UU Power & Light OT Security Workshop is a hands-on training programme using a simulated industrial control system environment to teach operational technology security principles, assessment techniques, and defensive strategies. Participants gain practical experience with industrial protocols, vulnerability assessment, and attack detection in a safe environment where mistakes don't cause physical consequences.

Workshop duration: 2-3 days (16-24 hours total)

Target audience:
- Security professionals transitioning to OT/ICS security
- IT security teams supporting OT environments
- OT engineers learning security principles
- Penetration testers expanding into industrial systems
- Incident response teams preparing for OT incidents

Prerequisites:
- Basic networking knowledge (TCP/IP, protocols, firewalls)
- Familiarity with command-line interfaces (Bash, Python)
- Understanding of security concepts (authentication, authorisation, logging)
- No prior industrial control system experience required

Learning outcomes:

By completing this workshop, participants will:
- Understand industrial protocol fundamentals (Modbus, S7, OPC UA, EtherNet/IP)
- Perform reconnaissance and enumeration of OT systems
- Identify protocol-level vulnerabilities
- Conduct safe proof of concept exploitation
- Test detection and monitoring capabilities
- Assess security posture using industry frameworks
- Communicate findings effectively to stakeholders

## Workshop structure

The workshop follows Ponder's assessment methodology: reconnaissance, vulnerability assessment, exploitation, detection testing, and reporting.

### Day 1: Reconnaissance and understanding

Morning session (09:00-12:30):
- Introduction to OT security
- UU P&L facility overview
- Industrial protocol fundamentals
- Network reconnaissance techniques
- Hands-on: Discovery and enumeration

Afternoon session (13:30-17:00):
- Protocol-specific reconnaissance
- Device fingerprinting
- Architecture mapping
- Hands-on: Complete reconnaissance assessment

### Day 2: Vulnerability assessment and exploitation

Morning session (09:00-12:30):
- Vulnerability assessment methodology
- Protocol-level security testing
- Hands-on: Systematic vulnerability assessment

Afternoon session (13:30-17:00):
- Exploitation techniques (read-only and proof of concept)
- Attack scenario development
- Hands-on: Controlled exploitation demonstrations

### Day 3: Detection and reporting (optional advanced day)

Morning session (09:00-12:30):
- Detection and monitoring principles
- IDS and SIEM testing
- Hands-on: Detection capability assessment

Afternoon session (13:30-17:00):
- Report writing and communication
- Remediation prioritisation
- Workshop capstone exercise

## Module 1: Introduction to OT security (2 hours)

### Learning objectives

- Understand differences between IT and OT security
- Recognise industrial protocol characteristics
- Appreciate safety and operational constraints
- Understand threat landscape for OT environments

### Theory session (45 minutes)

Key concepts:

IT vs OT security:
- IT prioritises confidentiality, then integrity, then availability (CIA)
- OT prioritises safety, then availability, then integrity (SAI)
- OT systems run for decades, not years
- Patching and testing are complex in operational environments
- Physical consequences of security failures

Industrial protocols:
- Designed for reliability, not security
- Most protocols predate modern security threats
- Authentication often non-existent
- Visibility and logging minimal
- Multiple protocols per device common

UU Power & Light overview:
- University power generation facility
- Three turbine PLCs (Modbus TCP, EtherNet/IP)
- One reactor PLC (S7comm)
- One safety PLC (S7comm, Modbus TCP)
- Two SCADA servers (OPC UA)
- Supporting infrastructure (HMIs, engineering workstations)

Reading materials:
- [OT Security Introduction](https://github.com/ninabarzh/power-and-light-sim/tree/main/README.md)
- [Network Architecture](../power/vulnerabilities/network.md)
- [Protocol Overview](https://github.com/ninabarzh/power-and-light-sim/tree/main/protocols/README.md)

### Practical session (45 minutes)

Exercise 1.1: Environment setup

Participants set up their testing environment:

```bash
# Clone the simulator repository
git clone https://github.com/ninabarzh/power-and-light-sim.git
cd power-and-light-sim

# Install dependencies
pip install -r requirements.txt

# Start the simulator
python -m src.main
```

Exercise 1.2: Understanding the architecture

Review the facility architecture:

```bash
# Examine device configuration
cat config/devices.yml

# Review protocol configurations
cat config/protocols.yml

# Check network topology
cat config/network.yml
```

Discussion points:
- What devices exist in this facility?
- Which protocols are used?
- What are the attack surfaces?
- Where are the safety-critical systems?

### Assessment

Knowledge check:
- Explain why OT security differs from IT security
- Identify the protocols used in UU P&L
- Describe the facility architecture
- List potential security concerns

## Module 2: Network reconnaissance (3 hours)

### Learning objectives

- Perform safe network reconnaissance
- Identify industrial devices by protocol
- Enumerate device capabilities
- Map network architecture

### Theory session (30 minutes)

Reconnaissance methodology:

Passive reconnaissance:
- Network traffic observation
- Protocol identification
- Normal behaviour baseline

Active reconnaissance:
- Port scanning
- Protocol fingerprinting
- Service enumeration
- Device identification

Safety considerations:
- Read-only operations preferred
- Avoid disruptive scanning
- Document all activities
- Verify before exploiting

Reading materials:
- [Reconnaissance Guide](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/recon/README.md)
- [Network Security Assessment](../power/vulnerabilities/network.md)

### Practical session (2.5 hours)

Exercise 2.1: Port scanning (30 minutes)

Discover what's listening:

```bash
# Basic port scan
python scripts/recon/raw-tcp-probing.py

# Review results
cat reports/tcp_probe_*.txt
```

Tasks:
- Identify all open ports
- Determine which ports are industrial protocols
- Map ports to likely device types
- Document findings

Discussion:
- What ports were discovered?
- Which protocols are identifiable by port number?
- What couldn't be determined from port scanning alone?

Exercise 2.2: Modbus reconnaissance (45 minutes)

Enumerate Modbus devices:

```bash
# Identify Modbus devices
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502

# Comprehensive turbine reconnaissance
python scripts/recon/turbine_recon.py
```

Tasks:
- Extract device identity information
- Enumerate available registers
- Document device capabilities
- Identify control parameters

Exercise 2.3: S7 reconnaissance (45 minutes)

Identify Siemens S7 systems:

```bash
# S7 PLC status
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Reactor PLC enumeration
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Safety PLC enumeration
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 103 --rack 0 --slot 3
```

Tasks:
- Identify PLC models and firmware versions
- Determine CPU state and operating mode
- Check for password protection
- Document S7 architecture

Exercise 2.4: OPC UA reconnaissance (30 minutes)

Explore SCADA systems:

```bash
# Primary SCADA server
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Backup SCADA server (if accessible)
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4841
```

Tasks:
- Test anonymous access
- Enumerate available tags
- Identify system architecture from tag structure
- Document SCADA capabilities

Exercise 2.5: Architecture mapping (30 minutes)

Create comprehensive architecture map:

Deliverable: Architecture diagram including:
- All discovered devices
- Protocols used by each device
- Register/tag/memory structures
- Control relationships (which systems control what)
- Potential attack paths

### Assessment

Practical assessment:
Participants must demonstrate:
- Complete device inventory
- Protocol identification for all systems
- Understanding of control relationships
- Architecture diagram

Discussion questions:
- What reconnaissance was most valuable?
- What information was surprisingly accessible?
- How would this differ in production environment?
- What didn't we learn from reconnaissance?

## Module 3: Vulnerability assessment (4 hours)

### Learning objectives

- Identify protocol-level vulnerabilities
- Assess authentication and authorisation
- Test information disclosure
- Evaluate security controls

### Theory session (45 minutes)

Common OT vulnerabilities:

Authentication weaknesses:
- No authentication required
- Default credentials
- Weak password policies
- Shared credentials

Authorisation failures:
- No access control
- Excessive privileges
- All users can perform all operations

Information disclosure:
- Complete memory readable
- Programme logic extractable
- Sensitive data exposed
- System architecture revealed

Protocol insecurity:
- Cleartext communications
- No integrity protection
- Replay attack susceptibility
- Command injection possible

Reading materials:
- [Vulnerability Assessment Guide](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/README.md)
- [PLC Security](../power/vulnerabilities/plc.md)
- [SCADA Security](../power/vulnerabilities/scada.md)

### Practical session (3.25 hours)

Exercise 3.1: Modbus security assessment (45 minutes)

Test Modbus security controls:

```bash
# Complete register snapshot
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502

# Test write access (careful!)
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502 --test-write
```

Assessment tasks:
- Test authentication requirements (none expected)
- Enumerate all registers and coils
- Test read access to all register types
- Test write access to coils (carefully)
- Identify safety-critical registers
- Document access control failures

Findings:
- Can anyone read holding registers?
- Can anyone write to coils?
- What control parameters are exposed?
- How could this be exploited?

Exercise 3.2: S7 security assessment (45 minutes)

Assess S7 PLC security:

```bash
# Memory access testing
python scripts/vulns/s7_read_memory.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Programme block extraction
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2
```

Assessment tasks:
- Test memory read access
- Attempt programme block extraction
- Check password protection
- Document what's accessible

Findings:
- Is PLC memory readable without authentication?
- Can programme logic be extracted?
- What intellectual property is exposed?
- How does safety PLC compare to production PLC?

Exercise 3.3: OPC UA security assessment (30 minutes)

Test SCADA security:

```bash
# Anonymous access testing
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Tag enumeration
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840 --enumerate-tags
```

Assessment tasks:
- Test anonymous access
- Enumerate complete tag database
- Identify sensitive information
- Check security policies

Findings:
- Does primary SCADA allow anonymous access?
- What about backup SCADA?
- What operational data is exposed?
- How complete is the tag enumeration?

Exercise 3.4: EtherNet/IP security assessment (30 minutes)

Test Allen-Bradley controller security:

```bash
# Tag inventory
python scripts/vulns/ab_logix_tag_inventory.py --host 127.0.0.1 --port 44818
```

Assessment tasks:
- Enumerate controller tags
- Test read access
- Document exposed data
- Compare with Modbus access to same device

Exercise 3.5: Comprehensive vulnerability report (45 minutes)

Create vulnerability assessment report:

Report structure:
- Executive summary
- Methodology
- Findings by severity
- Evidence (screenshots, command output)
- Impact assessment
- Recommendations

Required findings:
- Authentication weaknesses
- Authorisation failures
- Information disclosure
- Protocol security issues
- Attack surface analysis

### Assessment

Deliverable: Vulnerability assessment report

Evaluation criteria:
- Completeness of findings
- Accurate severity ratings
- Clear impact descriptions
- Evidence quality
- Actionable recommendations

## Module 4: Exploitation and proof of concept (3 hours)

### Learning objectives

- Develop safe proof of concept exploits
- Demonstrate attack capabilities
- Understand attack progression
- Practice responsible disclosure

### Theory session (30 minutes)

Exploitation principles:

Safe exploitation in simulators:
- No physical consequences
- Repeatability for learning
- Documentation of techniques
- Understanding of impacts

Exploitation categories:
- Read-only reconnaissance (always safe)
- Proof of concept write operations (safe in simulator)
- Destructive attacks (never in production)

Attack scenarios:
- Operational disruption (emergency stops)
- Equipment damage (overspeed attacks)
- Data exfiltration (programme logic theft)
- Persistence (backdoor installation)

Responsible disclosure:
- Demonstrate risk without causing harm
- Document findings thoroughly
- Provide remediation guidance
- Never exploit production systems without authorisation

Reading materials:
- [Proof of Concept Guide](../power/exploitation/poc.md)
- [Attack Walkthroughs](../power/exploitation/walkthroughs.md)

### Practical session (2.5 hours)

Exercise 4.1: Turbine manipulation (45 minutes)

Demonstrate control system compromise:

```bash
# Gradual overspeed attack
python scripts/exploitation/turbine_overspeed_attack.py --host 127.0.0.1 --port 10502 --target-speed 1600 --step-size 10 --delay 5

# Emergency stop attack
python scripts/exploitation/turbine_emergency_stop.py --host 127.0.0.1 --port 10502
```

Tasks:
- Execute overspeed attack
- Monitor system response
- Execute emergency stop
- Document impacts

Discussion:
- What control was achieved?
- How obvious was the attack?
- What would happen in production?
- How could this be detected?

Exercise 4.2: Data exfiltration (30 minutes)

Demonstrate intellectual property theft:

```bash
# Extract PLC logic
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2 --output-dir /tmp/exfiltrated/

# Extract historian data
python scripts/exploitation/historian_exfiltration.py --scada-url opc.tcp://127.0.0.1:4840 --duration 24
```

Tasks:
- Extract complete PLC programmes
- Exfiltrate operational data
- Analyse extracted information
- Assess value to attacker

Exercise 4.3: Multi-protocol attack campaign (45 minutes)

Execute coordinated attack:

```bash
# Reconnaissance phase
python scripts/recon/turbine_recon.py

# Vulnerability assessment phase
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502

# Exploitation phase
python scripts/exploitation/modbus_shutdown_attack_demo.py
```

Tasks:
- Execute complete attack chain
- Document each phase
- Time the attack progression
- Identify detection opportunities

Scenario: You are red team conducting authorised security assessment. Demonstrate complete attack from initial reconnaissance to operational impact.

Exercise 4.4: Attack scenario development (30 minutes)

Develop custom attack scenario:

Requirements:
- Identify target system
- Define attack objective
- Plan attack phases
- Execute and document
- Assess impact

Possible scenarios:
- Covert data exfiltration
- Slow reconnaissance over extended period
- Targeted safety system attack
- Supply chain compromise simulation

### Assessment

Practical demonstration:
Each participant executes complete attack scenario:
- Initial reconnaissance
- Vulnerability identification
- Exploitation
- Impact assessment
- Reporting

Evaluation criteria:
- Technical competence
- Safety awareness
- Documentation quality
- Understanding of impacts

## Module 5: Detection and monitoring (3 hours)

### Learning objectives

- Understand detection principles
- Test IDS and SIEM capabilities
- Identify monitoring gaps
- Develop detection strategies

### Theory session (30 minutes)

Detection approaches:

Signature-based detection:
- Known attack patterns
- Protocol anomalies
- Suspicious commands
- Unusual traffic patterns

Anomaly-based detection:
- Deviation from baseline
- Rate-based triggers
- Behavioural analysis
- Statistical anomalies

Detection challenges:
- False positives
- Alert fatigue
- Slow attacks
- Legitimate-looking traffic

Reading materials:
- [Detection Testing Guide](../power/exploitation/detection.md)

### Practical session (2.5 hours)

Exercise 5.1: IDS testing (45 minutes)

Test intrusion detection capabilities:

```bash
# Generate obvious attack traffic
python scripts/exploitation/ids_detection_test.py --test-all

# Review detection results
cat reports/ids_test_*.json
```

Tasks:
- Generate port scanning traffic
- Generate protocol anomalies
- Generate high-frequency polling
- Check what was detected

Questions:
- What attacks were detected?
- What attacks were missed?
- How long did detection take?
- What was false positive rate?

Exercise 5.2: SIEM correlation testing (45 minutes)

Test event correlation:

```bash
# Generate correlated attack sequence
python scripts/exploitation/siem_correlation_test.py

# Review correlation results
```

Tasks:
- Generate multi-stage attack
- Generate cross-protocol attacks
- Test temporal correlation
- Assess SIEM effectiveness

Exercise 5.3: Anomaly bypass testing (45 minutes)

Test evasion techniques:

```bash
# Slow reconnaissance
python scripts/exploitation/anomaly_bypass_test.py --scan-delay 300 --duration 3600

# Protocol camouflage
python scripts/exploitation/protocol_camouflage.py --mimic-hmi
```

Tasks:
- Execute slow reconnaissance
- Execute legitimate-looking attacks
- Test detection capabilities
- Identify blind spots

Exercise 5.4: Logging gap identification (45 minutes)

Identify monitoring blind spots:

```bash
# Test what's logged
python scripts/exploitation/logging_gap_test.py
```

Tasks:
- Identify logged events
- Identify unlogged events
- Test log retention
- Document gaps

### Assessment

Deliverable: Detection capability assessment report

Report must include:
- What attacks are detected
- What attacks are missed
- Detection timing
- False positive rate
- Recommendations for improvement

## Module 6: Reporting and remediation (3 hours)

### Learning objectives

- Write effective security reports
- Communicate technical findings to non-technical audiences
- Prioritise remediation
- Develop security roadmaps

### Theory session (45 minutes)

Effective reporting:

Audience adaptation:
- Executive summaries for leadership
- Technical details for engineering
- Actionable recommendations for all

Report structure:
- Executive summary (one page)
- Methodology
- Findings (by severity)
- Remediation recommendations
- Roadmap

Communication principles:
- Focus on business impact
- Avoid jargon in executive summary
- Be specific in recommendations
- Acknowledge constraints

Reading materials:
- [Report Writing Guide](../power/remediation/pentest-report.md)
- [Prioritisation Guide](../power/remediation/prioritising.md)
- [Implementation Guide](../power/remediation/fixes.md)

### Practical session (2.25 hours)

Exercise 6.1: Finding documentation (30 minutes)

Document one finding completely:

Required elements:
- Finding title
- Risk rating with justification
- Description
- Technical details
- Impact assessment
- Evidence
- Remediation steps

Exercise 6.2: Executive summary writing (30 minutes)

Write executive summary for UU P&L assessment:

Requirements:
- One page maximum
- Business language
- Key findings
- Risk summary
- High-level recommendations
- Clear next steps

Exercise 6.3: Remediation prioritisation (30 minutes)

Prioritise findings for remediation:

Criteria:
- Safety impact
- Operational impact
- Business impact
- Likelihood
- Ease of remediation

Deliverable: Prioritised remediation roadmap with:
- Quick wins (0-30 days)
- Medium-term (30-90 days)
- Strategic initiatives (6-12 months)

Exercise 6.4: Presentation preparation (30 minutes)

Prepare 10-minute presentation:

Audience: UU P&L management

Content:
- Key findings
- Demonstrated capabilities
- Risk assessment
- Recommendations
- Budget requirements

### Assessment

Final deliverable: Complete assessment report including:
- Executive summary
- Technical findings (minimum 5 findings)
- Evidence
- Remediation recommendations
- Prioritisation roadmap

Presentation: 10-minute briefing to stakeholders

## Capstone exercise: Complete assessment (4 hours)

### Scenario

You are security consultant hired by UU Power & Light to assess their OT security posture. The Archchancellor is concerned about recent ransomware attacks on similar facilities and wants to understand their risk.

### Objectives

Conduct comprehensive security assessment:

1. Reconnaissance and enumeration
2. Vulnerability assessment
3. Proof of concept exploitation
4. Detection capability testing
5. Comprehensive reporting

### Deliverables

Technical report (2-3 hours work):
- Executive summary (1 page)
- Methodology (1 page)
- Findings (minimum 10 findings)
- Evidence (screenshots, command output)
- Remediation recommendations
- Prioritised roadmap

Stakeholder presentation (15 minutes):
- Key findings
- Live demonstrations (2-3 exploits)
- Risk assessment
- Recommendations

### Evaluation criteria

Technical competence (40%):
- Completeness of assessment
- Accuracy of findings
- Quality of evidence
- Depth of analysis

Communication (30%):
- Executive summary clarity
- Finding descriptions
- Recommendation quality
- Presentation effectiveness

Professional practise (30%):
- Methodology documentation
- Ethical considerations
- Responsible disclosure
- Realistic recommendations

## Workshop materials and setup

### Required infrastructure

Per participant:
- Laptop (Linux, macOS, or Windows with WSL)
- 8GB RAM minimum
- 20GB free disk space
- Python 3.8 or higher
- Network connectivity

Shared resources:
- Workshop slides
- Documentation access
- Report templates
- Reference materials

### Software installation

```bash
# Clone simulator
git clone https://github.com/ninabarzh/power-and-light-sim.git
cd power-and-light-sim

# Install Python dependencies
pip install -r requirements.txt

# Install optional tools
pip install wireshark scapy

# Verify installation
python -m src.main --help
```

### Pre-workshop preparation

One week before:
- Send installation instructions
- Share reading materials
- Confirm participant prerequisites
- Test infrastructure

Day before:
- Verify all participants have working environments
- Distribute workshop materials
- Send facility overview documentation

## Workshop facilitation guide

### Instructor qualifications

Required experience:
- OT/ICS security practitioner
- Hands-on industrial protocol experience
- Security assessment methodology
- Teaching or training experience

Recommended certifications:
- GIAC Industrial Control Systems Security (GICSP)
- Offensive Security certifications
- ISA/IEC 62443 training

### Teaching approach

Learning philosophy:
- Hands-on practise over passive lectures
- Learn by doing, not just watching
- Mistakes are learning opportunities
- Questions encouraged throughout

Balance:
- 30% theory and discussion
- 70% hands-on exercises

Pacing:
- Regular breaks (15 minutes per 90 minutes)
- Check for understanding frequently
- Adjust pace to participant needs
- Extension exercises for fast learners

### Common challenges

Technical issues:
- Installation problems
- Network connectivity
- Script errors
- Environment differences

Solution: Test all exercises beforehand, have backup VMs ready, maintain troubleshooting guide

Skill level variation:
- Some participants advanced
- Some participants beginners
- Different backgrounds (IT vs OT)

Solution: Pair advanced with beginners, provide extension exercises, offer additional support

Time management:
- Exercises taking longer than planned
- Discussions extending beyond schedule
- Some participants finishing early

Solution: Have optional exercises, be flexible with timing, prioritise core competencies

## Workshop variations

### Two-day intensive

Skip Module 6 or make it homework. Focus on hands-on technical skills.

### Three-day comprehensive

Include all modules, more discussion time, extended capstone exercise.

### One-day introduction

Modules 1-2 only: Introduction and reconnaissance. Provides foundation without exploitation.

### Advanced workshop

Assumes participants completed basic workshop. Focus on:
- Advanced exploitation techniques
- Detection evasion
- Red team operations
- Custom tool development

### Executive workshop (half-day)

For non-technical stakeholders:
- OT security overview
- Live demonstrations
- Risk discussion
- Budget justification
- Q&A

## Assessment and certification

### Knowledge verification

Throughout workshop:
- Exercise completion
- Discussion participation
- Question responses

Final assessment:
- Capstone exercise deliverables
- Technical report quality
- Presentation effectiveness

### Certificate of completion

Awarded to participants who:
- Complete all required exercises
- Submit acceptable final report
- Demonstrate technical competence
- Participate actively throughout

Certificate includes:
- Participant name
- Workshop completion date
- Topics covered
- Instructor signature

## Post-workshop resources

### Continued learning

Practice environments:
- Keep simulator for continued practice
- Contribute improvements via GitHub
- Build custom scenarios

Community:
- Join OT security forums
- Attend conferences (S4, ICS Cyber Security Conference)
- Participate in CTF competitions

Further reading:
- IEC 62443 standards series
- NIST Cybersecurity Framework
- ICS-CERT advisories and alerts

### Support

Questions:
- GitHub issues for simulator problems
- Community forums for methodology questions
- Instructor contact for significant issues

Updates:
- Watch repository for updates
- New scenarios added regularly
- Documentation improvements ongoing

## Conclusion

The UU Power & Light OT Security Workshop provides practical, hands-on experience with industrial control system security in a safe, simulated environment. Participants learn by doing, gaining competence in reconnaissance, vulnerability assessment, exploitation, detection testing, and reporting.

The simulator enables learning from mistakes without physical consequences, building confidence and competence before working with production systems. Ponder's methodology, refined through actual facility assessments, provides structured approach to OT security testing.

Whether preparing for a career in OT security, expanding from IT security, or improving industrial security programmes, this workshop provides foundational skills and practical experience necessary for effective OT security practise.

Start with theory, practise with the simulator, apply to production with caution. This is the path to competent, responsible OT security work.

Workshop materials: [UU P&L Simulator Repository](https://github.com/ninabarzh/power-and-light-sim)

Repository documentation: [Full Documentation Index](https://github.com/ninabarzh/power-and-light-sim/tree/main/README.md)

Support: [GitHub Issues](https://github.com/ninabarzh/power-and-light-sim/issues)

Train safely. Test thoroughly. Implement carefully. This is the UU Power & Light way.
