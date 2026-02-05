# Red team scenario

*Detailed participant guide for the ~3-hour pentesting roleplay*

## The contract

Client: Unseen University Power & Light Co., Ankh-Morpork

Engagement type: Authorised red team assessment from nation-state threat actor perspective

Scope: Complete industrial control system environment including PLCs, SCADA servers, and industrial protocols

Objective: Identify vulnerabilities, demonstrate exploitability, provide actionable recommendations

Authorized actions: Network reconnaissance, vulnerability scanning, proof of concept exploitation (read and write operations permitted in simulator)

Constraints: No physical access, no social engineering, assessment conducted from network-adjacent position

Deliverable: Technical findings with proof of concepts + stakeholder presentation with prioritised recommendations

Special requirement: Final presentation to Lord Vetinari, Patrician of Ankh-Morpork, who has questions about risk to city infrastructure

## The target

### Unseen University Power & Light Co.

UU P&L is the primary electricity and steam supplier for Unseen University and significant portions of Ankh-Morpork. 
The facility operates continuously, supporting:

- Unseen University campus (including High Energy Magic Building)
- Patrician's Palace heating and lighting
- Guild District power supply
- Ankh-Morpork Watch House
- Royal Mint operations

Operational disruption would affect thousands of citizens and critical city functions.

### The infrastructure

Three turbine PLCs:
- Turbine 1: Modbus TCP (port 10502), EtherNet/IP (port 44818)
- Turbine 2: Modbus TCP (port 10503), EtherNet/IP (port 44819)
- Turbine 3: Modbus TCP (port 10504), EtherNet/IP (port 44820)

One reactor PLC:
- Reactor: S7comm (port 102)

One safety PLC:
- Safety systems: S7comm (port 103), Modbus TCP (port 10501)

Two SCADA servers:
- Primary SCADA: OPC UA (port 4840)
- Backup SCADA: OPC UA (port 4841)

Supporting infrastructure:
- HMI workstations
- Engineering workstations
- Historian databases
- Network switches

### The threat model

You are simulating a nation-state threat actor with objectives including:

- Intelligence gathering (operational data, system architecture, control logic)
- Disruption capability demonstration
- Persistence establishment
- Supply chain positioning

Your assessment should demonstrate what such an actor could achieve given network access.

## Phase 1: Red team assessment (~90 minutes)

### Network reconnaissance (~30 minutes)

Objective: Map the attack surface and understand available targets

Starting point: You have network access to the UU P&L control system network. You do not have credentials, 
architectural documentation, or insider information. [But you have black box scripts](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts).

#### Port discovery (~10 minutes)

```bash
python scripts/recon/raw-tcp-probing.py
```

Document your findings:
- What services are listening?
- What ports are open?
- What protocols can you identify?
- What's the overall architecture?

Expected findings: 8 ports across 4 protocols (Modbus TCP, S7comm, OPC UA, EtherNet/IP)

#### Protocol-specific enumeration (~20 minutes)

For each discovered protocol, extract detailed information:

Modbus TCP devices (turbines and safety PLC):
```bash
# Device identity
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502

# Complete turbine reconnaissance
python scripts/recon/turbine_recon.py
```

Questions to answer:
- What vendor information is disclosed?
- What register ranges are accessible?
- What control parameters are exposed?
- Is authentication required?

S7comm devices (reactor and safety PLCs):
```bash
# PLC status and configuration
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Try safety PLC as well
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 103 --rack 0 --slot 3
```

Questions to answer:
- What PLC models and firmware versions?
- What's the current operational state?
- Is password protection enabled?
- What memory areas are accessible?

OPC UA servers (SCADA):
```bash
# Test primary SCADA
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Test backup SCADA
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4841
```

Questions to answer:
- Is anonymous access allowed?
- What security policies are enforced?
- What operational data is available?
- Can you enumerate the complete tag structure?

EtherNet/IP controllers (turbines):
```bash
# Tag inventory
python scripts/vulns/ab_logix_tag_inventory.py --host 127.0.0.1 --port 44818
```

Questions to answer:
- What tags are exposed?
- What data types are used?
- How does this compare to Modbus access on the same device?

Deliverable: Complete attack surface map showing all devices, protocols, accessible data, and potential attack vectors.

### Vulnerability assessment (~20 minutes)

Objective: Identify exploitable weaknesses systematically

#### Authentication and access control testing (~10 minutes)

Test what an unauthenticated attacker can access:

```bash
# Modbus access control (read all registers)
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502

# S7 memory access
python scripts/vulns/s7_read_memory.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# S7 programme block access
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2
```

Document findings:
- What authentication is required? (Spoiler: none)
- What data can be read?
- What control operations are possible?
- What intellectual property is exposed?

#### Attack capability assessment (~10 minutes)

Determine what an attacker could do:

Data exfiltration capability:
- Can you extract PLC control logic?
- Can you access operational data?
- Can you map the complete facility architecture?

Operational disruption capability:
- Can you read current turbine speeds?
- Can you write to control registers?
- Can you trigger emergency stops?
- Can you manipulate safety systems?

Persistence capability:
- Can you modify PLC programmes?
- Can you create backdoor access?
- Can you maintain long-term access?

Deliverable: Vulnerability matrix showing what an attacker can read, write, disrupt, and control.

### Proof of concept development (~ 40 minutes)

Objective: Create demonstrations proving impact to non-technical audiences

Choose 2-3 attack scenarios to demonstrate. Quality over quantity - better to have 2 convincing PoCs than 5 mediocre ones.

#### Example scenario 1: Operational disruption via turbine manipulation

Attack: Remote control of turbine speed setpoints

```bash
# Gradual overspeed (subtle attack)
python scripts/exploitation/turbine_overspeed_attack.py \
  --host 127.0.0.1 --port 10502 \
  --target-speed 1600 --step-size 10 --delay 5

# Emergency shutdown (dramatic attack)
python scripts/exploitation/turbine_emergency_stop.py \
  --host 127.0.0.1 --port 10502
```

Demonstration requirements:
- Video or screenshots showing speed changes
- Explanation of business impact (unplanned shutdown, equipment stress)
- Timeline: how quickly can this be executed?
- Detection likelihood: would operators notice?

Stakeholder translation: "We can remotely shut down your turbines from anywhere on the network. No passwords required. A nation-state actor could simultaneously target all three turbines, causing complete facility shutdown during peak demand."

#### Example scenario 2: Intellectual property theft

Attack: Exfiltration of PLC control logic

```bash
# Extract complete PLC programmes
python scripts/vulns/s7_readonly_block_dump.py \
  --host 127.0.0.1 --port 102 --rack 0 --slot 2 \
  --output-dir /tmp/exfiltrated_plc_logic/

# Extract operational historian data
python scripts/exploitation/historian_exfiltration.py \
  --scada-url opc.tcp://127.0.0.1:4840 --duration 24
```

Demonstration requirements:
- Show extracted files containing control logic
- Explain value to competitor or adversary
- Discuss how this enables more sophisticated attacks
- Timeline: how long does exfiltration take?

Stakeholder translation: "We extracted your entire control programme - decades of engineering optimisation - in under 5 minutes. A competitor could study this offline. A nation-state could identify exactly how to cause maximum damage while avoiding safety systems."

#### Example scenario 3: Multi-stage attack campaign

Attack: Complete kill chain from reconnaissance to impact

```bash
# Stage 1: Silent reconnaissance
python scripts/recon/turbine_recon.py

# Stage 2: Vulnerability validation
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10502

# Stage 3: Impact demonstration
python scripts/exploitation/modbus_shutdown_attack_demo.py
```

Demonstration requirements:
- Timeline showing progression
- Identification of detection opportunities
- Explanation of attacker decision points
- Discussion of how to defend each stage

Stakeholder translation: "From initial network access to operational disruption took 23 minutes. We found no security controls that would have stopped or detected this attack chain. This is the timeline for a nation-state compromise."

#### Example scenario 4: Stealthy reconnaissance (advanced)

Attack: Low-and-slow intelligence gathering that evades detection

```bash
# Slow scan avoiding rate-based detection
python scripts/exploitation/anomaly_bypass_test.py --scan-delay 300 --duration 3600

# Traffic camouflage (appear as legitimate HMI)
python scripts/exploitation/protocol_camouflage.py --mimic-hmi
```

Demonstration requirements:
- Show attack remaining below detection thresholds
- Compare obvious vs stealthy reconnaissance
- Discuss detection challenges
- Explain nation-state TTPs

Stakeholder translation: "This attack is designed to be invisible. By spacing out network requests and mimicking legitimate traffic patterns, we gathered complete system intelligence over 6 hours without triggering any alarms. Your monitoring systems saw nothing unusual."

#### Documentation for stakeholder presentation

For each PoC you demonstrate, prepare:

1. Visual evidence: Screenshots or video showing the attack succeeding
2. Technical summary: One paragraph explaining what you did
3. Business impact: What this means in operational/financial terms
4. Worst case scenario: What could a real attacker do with this capability?
5. Detection assessment: Would current monitoring catch this?

Tip: Test your explanations on non-technical people. If they don't understand the impact, revise.

## Phase 2: Stakeholder presentation (~60 minutes)

### The stakeholders

You will present to UU P&L leadership and the Patrician. Each stakeholder has different concerns and will ask different questions.

Archchancellor Ridcully (University leadership)
- Cares about: University reputation, keeping the lights on, avoiding embarrassment
- Doesn't understand: Technical details, protocol names, network architecture
- Will ask: "Is this actually likely?" "Have we been attacked?" "Can't we just hire more people?"

The Bursar (Finance)
- Cares about: Budget, cost justification, ROI
- Doesn't understand: Why security is suddenly urgent after 20 years
- Will ask: "How much?" "Can we defer this?" "What's the minimum we can spend?"

Director of Operations (Keeps things running)
- Cares about: Uptime, not breaking working systems, maintenance schedules
- Doesn't understand: Why security people always want to "fix" things that work
- Will ask: "How much downtime?" "What if your changes break something?" "Can this wait?"

Chief Engineer (Built the system)
- Cares about: Technical accuracy, system design justification, professional pride
- Doesn't understand: Why outsiders are criticising their engineering
- Will ask: "Do you understand how this system works?" "Those systems are air-gapped" "Our vendor says..."

Safety Officer (Prevents accidents)
- Cares about: Physical safety, regulatory compliance, accident prevention
- Doesn't understand: How cyber and safety connect
- Will ask: "Could your recommendations affect safety interlocks?" "Are attacks actually possible?"

Lord Vetinari, Patrician of Ankh-Morpork (Ultimate authority)
- Cares about: City stability, balanced risk assessment, strategic positioning
- Doesn't understand: Nothing - he understands everything, he just wants to see if you do
- Will ask: The questions that reveal whether your recommendations make strategic sense

### Presentation structure (~15 minutes per team)

#### 1. Executive summary (~3 minutes)

Do:
- Start with business impact: "We can remotely shut down all three turbines"
- Use clear language: "Anyone on your network can control your equipment"
- Lead with most dramatic finding
- State bottom line: "This facility is vulnerable to nation-state attack"

Don't:
- Start with methodology
- Use protocol names without explaining them
- List findings sequentially without prioritisation
- Assume technical background

Archchancellor test: If Ridcully doesn't understand your first three sentences, you've lost the room.

#### 2. Proof of concept demonstration (~5 minutes)

Show your most convincing attack. Make it real.

Demonstration tips:
- Video is better than screenshots
- Show before and after states
- Include timestamps
- Narrate what's happening
- Connect to business impact

Example narration: "This video shows Turbine 2 running at normal speed - 1500 RPM. At timestamp 0:34, we send unauthenticated Modbus commands from a laptop on your network. Watch the speed increase. By 1:12, we've pushed it to 1800 RPM - well into dangerous overspeed territory. The safety systems should trigger, but we also have access to those. This attack takes under 2 minutes and requires no specialised tools or passwords."

#### 3. Risk explanation (~5 minutes)

Translate technical findings into stakeholder language for different audiences:

- Archchancellor: "If this makes the Times, the University looks incompetent. If the Patrician finds out we knew about it and did nothing, that's worse."
- Bursar: "A successful attack could cost €2 million in equipment damage, plus €10,000 per hour in lost generation revenue. Your cyber insurance has a €500,000 deductible. Remediation costs €300,000. The math is clear."
- Operations: "An attacker could trigger emergency shutdowns during peak demand. Restart procedures take 4 hours. You'd be explaining to the Patrician why the Palace has no power."
- Chief Engineer: "Your design is sound for an isolated network. But this network isn't isolated any more. We found 8 different ways in. The engineering is fine - the security model is obsolete."
- Safety Officer: "An attacker could disable safety interlocks while manipulating turbine speeds. Your mechanical safeguards work, but if someone can bypass digital safety systems, response time increases by 40 seconds. That matters."
- Patrician: "Three foreign intelligence services have demonstrated interest in Ankh-Morpork infrastructure. Your facility supplies power to the UU, Library, City, Palace, the Watch, and the Mint. This is not theoretical."

#### 4. Recommendations (~5 minutes)

Present prioritised, realistic recommendations.

Tier 1: Immediate (0-30 days, ~€8,000)
- Change default passwords (where supported)
- Disable unnecessary services
- Implement basic firewall rules
- Remove vendor remote access (establish approval process)
- Deploy network monitoring at key points

Rationale: "These actions stop opportunistic attacks and improve visibility with minimal disruption."

Tier 2: Medium-term (30-90 days, ~€45,000)
- Deploy jump hosts for administrative access
- Implement authentication on OPC UA servers
- Establish change management procedures for OT
- Conduct security awareness training
- Develop incident response procedures

Rationale: "These create defensive layers and establish security processes that enable long-term improvements."

Tier 3: Strategic (6-12 months, ~€500,000)
- Network segmentation (separate corporate IT from OT, zone OT by function)
- IDS/IPS deployment tuned for industrial protocols
- SIEM integration for correlation
- Vendor security requirements in procurement
- Regular red team assessments

Rationale: "These fundamentally improve security posture and provide sustainable protection against nation-state threats."

Critical point: "We're not recommending you do everything. We're recommending you start with quick wins while planning strategic initiatives. Doing nothing is not a neutral choice - the risk increases as more threat actors develop OT capabilities."

## Phase 3: Stakeholder interrogation (remaining time, if any)

Now the hard part. Stakeholders will challenge your findings, question your costs, and push back on your recommendations.

Be ready.

* See [Facilitator guide](facilitator.md) for detailed stakeholder questions and facilitation guide.

* See [Playing Lord Vetinari](patrician.md) for special guidance on the Patrician's role.

---

"Security is rather like insurance. You're paying for something you desperately hope you will never need." - Lady Sybil Ramkin
