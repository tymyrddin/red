# Safety system testing

The systems we absolutely must not break.

Safety Instrumented Systems (SIS) are the systems that keep industrial processes from turning into disasters. When 
pressure gets too high, they open relief valves. When temperature exceeds limits, they shut down reactions. When 
everything else fails, they activate emergency shutdowns. They're the last line of defence between "minor operational 
issue" and "major incident requiring evacuations and HSE investigations".

Testing safety systems during a penetration test is like juggling chain saws whilst blindfolded. The margin for 
error is essentially zero, the consequences of mistakes are severe, and there's a very good chance that multiple 
people will shout at you if anything goes wrong. Lord Vetinari has a similar view of the Patrician's Palace's 
security systems: they're to be reviewed, analysed, and understood, but never actually tested in a way that might 
result in the Patrician being vulnerable, even briefly. The consequences of such a test failing would be 
career-limiting, which in Ankh-Morpork terms means something quite specific and permanent.

The fundamental challenge with safety system testing is that you need to verify security without compromising safety. 
You need to understand whether an attacker could defeat safety systems without actually defeating the safety systems. 
You need to prove vulnerabilities exist without demonstrating those vulnerabilities in a way that could cause harm. 
It requires a level of restraint that's quite foreign to typical penetration testing methodology, where "proof" 
usually means "I actually did the thing and here's the evidence".

At UU P&L, the safety systems were the crown jewels of the facility. They'd been engineered to SIL-3 standards 
(Safety Integrity Level 3, which means they're allowed to fail no more than once per thousand years), commissioned 
by certified specialists, and extensively tested during startup. They were also, according to management, 
"completely off-limits for security testing under any circumstances whatsoever, have we made ourselves clear?"

We made ourselves clear that we understood, and then proceeded to analyse the safety systems using methods that 
didn't involve touching them, connecting to them, or being within arm's reach of them. This is what observation-only 
assessment looks like in practice.

## SIS architecture and principles

Before you can assess safety system security, you need to understand safety system design:

### Safety instrumented systems architecture

Production Control System:
- PLCs running production logic
- Optimizes output, efficiency, quality
- Connected to enterprise network
- Can fail without immediate safety risk

Safety Instrumented System (SIS):
- Separate PLCs running only safety logic
- Monitors for unsafe conditions
- Completely independent from production control
- Failure means production stops (fail-safe)
- MUST NOT be compromised

Key principle: Independence
- Separate hardware
- Separate network
- Separate power supplies
- Separate sensors (where practical)
- No shared dependencies with production systems

The independence principle is critical. If production control and safety control share hardware, a compromise of production could affect safety. If they share networks, a network attack could affect both. The entire safety system design revolves around ensuring that no single failure (including cyberattack) can both cause an unsafe condition AND prevent the safety system from detecting it.

### Safety Integrity Levels (SIL)

IEC 61508 defines four Safety Integrity Levels (SIL):

4. Probability of failure on demand: 10^-5 to 10^-4 (1 failure per 10,000 to 100,000 demands): Essentially never fails
       
3. Probability of failure on demand: 10^-4 to 10^-3 (1 failure per 1,000 to 10,000 demands): Very rarely fails
       
2. Probability of failure on demand: 10^-3 to 10^-2 (1 failure per 100 to 1,000 demands): Occasionally fails
       
1. Probability of failure on demand: 10^-2 to 10^-1 (1 failure per 10 to 100 demands): Sometimes fails

Higher SIL ratings mean more rigorous engineering, more redundancy, more testing, and significantly higher costs. 
Most industrial safety systems are SIL-2 or SIL-3. SIL-4 is reserved for truly critical applications (nuclear power, 
aviation, etc.) where failure is essentially unacceptable.

### Layers of protection analysis (LOPA)

Safety systems are designed in layers:

1. Process design (inherently safer design)
2. Basic controls (keep process in normal range)
3. Alarms and operator intervention
4. Automatic safety systems (SIS)
5. Physical protection (relief valves, rupture discs)
6. Emergency response

Each layer reduces risk by approximately 10x to 100x. Multiple layers provide defence in depth. The philosophy is that 
no single failure (including malicious action) should result in an accident.

## IEC 61508 and 61511 standards

IEC 61508 is the general standard for safety systems. IEC 61511 is the sector-specific version for process industries. Understanding these standards helps you understand what's required versus what's recommended versus what's actually implemented.

### Key security-relevant requirements

Hardware independence:
- Requirement: SIS hardware must be separate from production control
- Reality: Usually implemented (separate PLCs)
- Security impact: Compromise of production PLC shouldn't affect SIS

Software independence:
- Requirement: SIS logic must be separate from production logic
- Reality: Usually implemented (separate programs)
- Security impact: Malicious production logic can't directly affect safety

Network independence:
- Requirement: SIS should have separate communication network
- Reality: Sometimes implemented, often "separate VLAN"
- Security impact: Network attacks could affect both systems

Access control:
- Requirement: Restricted access to SIS configuration
- Reality: Varies widely in implementation
- Security impact: Who can modify safety logic?

The standards were written primarily for functional safety (preventing accidents) rather than security (preventing 
attacks). They assume that personnel are trained and trustworthy, not malicious. This leaves gaps in cybersecurity 
requirements.

### IEC 62443 overlay

IEC 62443 adds cybersecurity requirements specifically for industrial automation:

Security Levels (SL):

1. Protection against casual or coincidental violation (Protect against mistakes)

2. Protection against intentional violation using simple means (Protect against unsophisticated attacker)

3. Protection against intentional violation using sophisticated means (Protect against skilled attacker with moderate resources)

4. Protection against intentional violation using sophisticated means with extended resources (Protect against nation-state attacker)

Most OT environments target SL-2 or SL-3. SL-4 is rare outside of critical national infrastructure.

## Testing without interfering

The golden rule of safety system testing: observation only. Never connect to, transmit to, or interact with safety 
system hardware during testing.

### Documentation review

Start with paperwork. Documents to request:

1. Safety requirements specification (SRS)
   - What hazards exist?
   - What protective functions are required?
   - What are the safety limits?

2. SIL verification reports
   - How was safety integrity level achieved?
   - What redundancy exists?
   - What failure modes were considered?

3. Cause and effect matrices
   - What sensors trigger what actions?
   - What's the logic for each safety function?

4. Functional safety assessment (FSA) reports
   - What testing was performed?
   - What vulnerabilities were identified?
   - What mitigations were implemented?

5. Network architecture diagrams
   - How is SIS networked?
   - What separation exists from production systems?
   - What remote access exists?

6. Access control procedures
   - Who can modify SIS logic?
   - What approval processes exist?
   - How are changes documented?

At UU P&L, the documentation review revealed several concerning items:

- The safety system specification required "complete network separation" from production control. The implementation used "separate VLANs on the same physical switches". Technically separate, but not as independent as specified.
- Access control procedures required "dual approval for all safety logic changes". In practice, the engineering manager had a copy of both approval keys "for emergencies", eliminating the dual control.
- The SIL verification assumed that "configuration access requires physical presence at the facility". Remote access capabilities weren't considered in the safety analysis.

None of these findings required touching the safety systems. We just read documents and asked questions.

### Architecture analysis

Review network architecture from a security perspective. Questions to answer:

1. Physical separation:
   - Is SIS on separate hardware? (Usually yes)
   - Is SIS on separate network? (Varies)
   - Are there any shared components? (Sometimes)

2. Network access:
   - Can production network reach SIS? (Shouldn't, but often can)
   - Can enterprise network reach SIS? (Definitely shouldn't)
   - What remote access exists? (Often more than documented)

3. Update mechanisms:
   - How is SIS firmware updated?
   - How is safety logic updated?
   - Can updates be malicious?

4. Monitoring and logging:
   - Are SIS changes logged?
   - Are logs tamper-proof?
   - Who reviews logs?

Analysis at UU P&L:

Physical separation: Good
- Separate PLCs from production
- Separate power supplies
- Independent sensors for critical measurements

Network separation: Partial
- Separate VLAN
- But same physical infrastructure
- Engineering workstations can reach both production and safety networks

Access control: Weak
- Remote access via vendor VPN reaches safety network
- No authentication beyond standard PLC password
- Password shared among multiple vendors

Change management: Partial
- Changes require documented approval
- But audit trail can be edited
- No cryptographic verification of changes

### Passive network observation

If you can observe network traffic to/from SIS without interfering with it:

```bash
# Network tap (physical device that copies traffic)
# NEVER use a switch port mirror for safety systems
# Switch port mirrors can affect switch performance
# Use a proper network tap (passive optical or copper)

# Capture traffic
tcpdump -i eth0 -w sis_traffic.pcap

# Analyse offline
wireshark sis_traffic.pcap

# Look for:
# - What protocols are used?
# - Is traffic encrypted?
# - What devices communicate with SIS?
# - Are there any unexpected connections?
```

At UU P&L, we used a passive optical network tap (which physically cannot affect the network) to observe SIS network traffic. We discovered:

- Expected traffic: HMI to SIS (Modbus TCP, every 1 second)
- Expected traffic: Engineering workstation to SIS (occasional, during day shift)
- Unexpected traffic: Unknown device (192.168.5.247) connecting to SIS multiple times per day
- Unexpected traffic: Vendor VPN gateway forwarding traffic to SIS
- Unexpected traffic: Unencrypted FTP transfers (firmware updates?)

The unknown device (192.168.5.247) turned out to be a data historian that someone had configured to archive SIS alarm logs. Nobody had documented this connection. It wasn't malicious, but it was unintended network access to the safety system.

## Safety versus security trade-offs

Safety and security often conflict:

### Redundancy versus attack surface

Safety principle: Redundancy improves safety
- Three pressure sensors (2oo3 voting: 2 out of 3 must agree)
- Two safety PLCs (1oo2: 1 out of 2 can shut down process)
- Multiple shutdown valves

Security principle: Redundancy increases attack surface
- Three pressure sensors = three devices that could be compromised
- Two safety PLCs = two attack targets
- More devices = more complexity = more vulnerabilities

### Fail-safe versus availability

Safety principle: When in doubt, shut down
- If sensor fails, assume unsafe condition
- If logic detects anomaly, trigger shutdown
- False positives are acceptable (production stops but safe)

Security principle: Denial of service is an attack
- Attacker triggering false shutdowns is a problem
- Nuisance alarms cause operational issues
- Must balance safety and availability

### Simplicity versus functionality

Safety principle: Simple systems are more reliable
- Minimal logic
- Limited functionality
- Proven designs
- Conservative approach

Security principle: Modern security needs modern features
- Encryption requires computational resources
- Authentication requires user management
- Logging requires storage
- These conflict with simplicity

At UU P&L, we identified several specific trade-offs:

### Trade-off 1: Remote access

Safety perspective: Engineers need remote access for emergency troubleshooting. If turbine overspeed occurs at 2 AM, waiting for engineer to drive to facility could result in equipment damage.

Security perspective: Remote access is an attack vector. If engineers can connect remotely, attackers might be able to as well.

Resolution: Implemented one-time-use VPN tokens with strict time windows and activity logging. Remote access remained possible but was more controlled.

### Trade-off 2: Vendor access

Safety perspective: Equipment vendors must be able to diagnose problems quickly. Safety system failures need immediate expert response.

Security perspective: Permanent vendor access is a persistent backdoor. Vendors may have poor security practices.

Resolution: Vendor access changed from "always-on VPN" to "scheduled access with advance notice". Vendor notifies facility 24 hours before connection, access is monitored, credentials are single-use.

### Trade-off 3: Update management

Safety perspective: Safety systems should rarely be updated. Every change is risk. If it's working, leave it alone.

Security perspective: Unpatched systems accumulate vulnerabilities. Should update regularly for security patches.

Resolution: Risk-based approach. Security patches assessed for safety impact. Critical security updates implemented with full safety testing. Non-critical updates deferred until planned maintenance windows.

## Observation-only approaches

Practical methods for security assessment without touching safety systems:

### Interview-based assessment

Talk to people who work with the systems:

Questions for operators:
- How often do safety systems activate?
- What causes false alarms?
- Do you ever bypass safety systems? (They won't admit this directly)
- What happens when you need to work on equipment that's protected?

Questions for engineers:
- How do you make changes to safety logic?
- What testing is performed after changes?
- How do you access safety systems remotely?
- What vendor access exists?

Questions for maintenance:
- How do you maintain safety system hardware?
- What spare parts are kept?
- Are there any "temporary" bypasses?
- How do you handle sensor failures?

The key is to ask open-ended questions and listen for security implications that the interviewee might not recognise. 
When an operator mentions "we have to jump the safety interlock when cleaning the vessel", they're describing a 
security-relevant bypass procedure.

### Configuration review (offline)

Request backups of safety PLC programs for offline analysis:

[🐙 Safety PLC Configuration Analysis (offline only)](https://github.com/ninabarzh/power-and-light/blob/main/topics/safety_plc_analysis.py)

### Physical inspection (visual only)

Walk the facility with engineers and observe. Visual inspection checklist:

- Are safety PLCs physically secured? (Locked cabinets? Tamper seals?)
- Are there any unauthorised connections? (Extra network cables? USB devices?)
- Are there any bypass switches? (Physical switches that disable safety functions?)
- Is there evidence of maintenance bypasses? (Jumper wires? Temporary connections?)
- Are sensors secure? (Could they be physically manipulated?)
- Are there any remote access devices? (Cellular modems? WiFi adapters?)

At UU P&L, physical inspection revealed:

- Safety PLC cabinet had a padlock, but the key was hanging on a hook inside the control room where anyone could access it
- Two network cables connected to safety PLC that weren't documented in network diagram
- A pressure sensor had a manual isolation valve that could "bypass" the sensor (engineering control, but not documented)
- A USB drive was plugged into the safety PLC (turned out to be for data logging, but nobody had approved it)

None of these issues required touching the safety systems to discover. Visual inspection and asking questions was sufficient.

## The Librarian approach to safety systems

The Librarian of Unseen University is an orangutan who takes the security of his library very seriously. He has strong opinions about people interfering with his books, and these opinions are backed by approximately 300 pounds of muscle and a tendency toward direct physical communication when annoyed. The key to working in the Library is understanding that while the Librarian is responsible for security, you can still conduct research, you just need to do it in ways that don't upset him.

Safety systems should be treated with similar respect. They're critical to facility safety, they're someone else's responsibility (the safety engineer, not the security tester), and interfering with them will result in consequences that are professional rather than physical but no less career-impacting.

The approach that works:

1. Acknowledge that safety takes precedence over security testing
   - If safety and security conflict, safety wins
   - This isn't negotiable
   
2. Work with the safety team, not around them
   - Safety engineers understand their systems better than you do
   - They can identify security issues you might miss
   - They can approve or reject testing methods
   
3. Use observation and analysis rather than active testing
   - You can learn almost everything from documentation and observation
   - Active testing of safety systems is rarely necessary
   - When it is necessary, do it in simulation first

4. Focus recommendations on "security without compromising safety"
   - Don't recommend removing safety features for security
   - Don't recommend changes that increase safety risk
   - Find solutions that improve both

At UU P&L, we wrote a separate section of the report specifically for safety systems, titled "Safety System Security Assessment (Observation Only)". It acknowledged upfront that we hadn't tested the safety systems directly, explained our methodology (documentation review, architecture analysis, passive observation), and provided recommendations that explicitly considered safety implications.

The safety team appreciated this approach. They reviewed our findings, provided additional context we'd missed, and worked with us on recommendations that they felt comfortable implementing. The result was better security without compromising the safety systems they'd spent years engineering and certifying.

The key insight is that safety systems don't need to be tested the same way as production systems. The stakes are too high, the margin for error is too small, and the relationship between the penetration tester and the safety team is too important to risk by being overly aggressive. Sometimes the best test is the one you don't perform, as long as you can still provide valuable findings through analysis and observation.

