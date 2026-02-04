# Safety system testing: The systems we absolutely must not break

*Or: How Ponder Tested Safety Systems Without Actually Testing Safety Systems*

## The delicate balance

Safety Instrumented Systems (SIS) are the systems that keep industrial processes from turning into disasters. When pressure gets too high, they open relief valves. When temperature exceeds limits, they shut down reactions. When everything else fails, they activate emergency shutdowns. They're the last line of defence between "minor operational issue" and "major incident requiring evacuations and HSE investigations".

Testing safety systems during a penetration test is like juggling chainsaws whilst blindfolded. The margin for error is essentially zero, the consequences of mistakes are severe, and there's a very good chance that multiple people will shout at you if anything goes wrong. Lord Vetinari has a similar view of the Patrician's Palace's security systems: they're to be reviewed, analysed, and understood, but never actually tested in a way that might result in the Patrician being vulnerable, even briefly. The consequences of such a test failing would be career-limiting, which in Ankh-Morpork terms means something quite specific and permanent.

The fundamental challenge with safety system testing is that you need to verify security without compromising safety. You need to understand whether an attacker could defeat safety systems without actually defeating the safety systems. You need to prove vulnerabilities exist without demonstrating those vulnerabilities in a way that could cause harm.

It requires a level of restraint that's quite foreign to typical penetration testing methodology, where "proof" usually means "I actually did the thing and here's the evidence".

## Safety systems in the simulator

The UU P&L simulator includes a safety PLC in its architecture:

Safety PLC specifications:
- Protocol: S7comm (port 103)
- Alternative protocol: Modbus TCP (port 10503)
- Purpose: Emergency shutdown and safety interlocks
- Independence: Separate from production control PLCs

The safety PLC exists in the simulator architecture but requires careful consideration during testing. The simulator 
is a safe environment where mistakes don't cause physical consequences, but developing good safety testing habits 
matters. If you learn to test safety systems carelessly in a simulator, you'll test them carelessly in production, 
and that's when people might get hurt.

## What the simulator allows

Because the simulator runs entirely in software with no physical consequences, it permits safety system testing that would be unacceptable in production:

### Read-only reconnaissance

[S7 PLC status dump](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_plc_status_dump.py) works against the safety PLC:

```bash
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 103 --rack 0 --slot 3
```

What this reveals:
- PLC model and firmware version
- CPU state and operating mode
- Whether password protection is enabled
- Module configuration

Safety impact in simulator: None (read-only operation)

Safety impact in production: Minimal (read-only, but some safety PLCs log connection attempts)

### Memory reading

[S7 memory reading](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_read_memory.py) can access safety PLC memory:

```bash
python scripts/vulns/s7_read_memory.py --host 127.0.0.1 --port 103 --rack 0 --slot 3
```

What this reveals:
- Data block contents (safety logic parameters)
- Process image (current sensor states)
- Marker memory (internal variables)
- Timer and counter values

Safety impact in simulator: None (read-only operation)

Safety impact in production: Low (read-only, but provides attacker with safety system understanding)

### Logic extraction

[S7 programme block dump](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_readonly_block_dump.py) can extract safety logic:

```bash
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 103 --rack 0 --slot 3
```

What this reveals:
- Organisation blocks (OB): Safety programme structure
- Function blocks (FB): Safety function implementations
- Data blocks (DB): Safety parameters and setpoints
- Complete safety logic

Safety impact in simulator: None (read-only operation, intellectual property concern)

Safety impact in production: Moderate (reveals safety system design to attacker, aids in attack planning)

### Modbus access to safety systems

The safety PLC also responds to Modbus TCP on port 10503:

```bash
python scripts/vulns/modbus_coil_register_snapshot.py --host 127.0.0.1 --port 10503
```

What this reveals:
- Safety system registers and coils
- Emergency stop status
- Safety interlock states
- Alternative protocol access path

Finding: Safety system accessible via two different protocols (S7 and Modbus), increasing attack surface

## What the simulator demonstrates about safety security

Testing the safety PLC in the simulator reveals several security concerns common in real safety systems:

### Lack of authentication

Neither S7 nor Modbus access to the safety PLC requires authentication:
- No password protection on S7 connection
- No authentication mechanism in Modbus protocol
- Network access equals system access

Finding: If attacker reaches safety system network, they have complete read access to safety logic and current safety states.

### Multiple protocol access

The safety PLC supports both S7comm and Modbus:
- Two different protocols to monitor
- Two different attack surfaces
- Blocking one protocol doesn't prevent access

Finding: Safety system defence requires protecting multiple protocols simultaneously.

### Information disclosure

Read-only access provides attackers with valuable information:
- Complete safety logic (how to trigger safety systems)
- Safety limits and thresholds (how close to safety boundaries can attacker push?)
- Interlock conditions (which interlocks must be defeated?)
- Safety system architecture (what redundancy exists?)

Finding: Even without write access, attackers gain knowledge needed for sophisticated attacks.

## What the simulator doesn't test (correctly)

While the simulator allows safety system testing, it doesn't simulate several critical aspects:

### Safety integrity levels (SIL)

Real safety systems are designed to SIL-2 or SIL-3 standards:
- Redundant sensors (2oo3 voting)
- Redundant PLCs (1oo2 architecture)
- Fail-safe design (failures trigger shutdowns)
- Proof testing and validation

The simulator's safety PLC is a single instance without redundancy. This doesn't represent real safety system architecture.

### Physical independence

Real safety systems have physical separation:
- Separate hardware from production control
- Separate power supplies
- Separate network infrastructure
- Independent sensors where practical

The simulator runs everything on localhost. There's no actual physical or network independence.

### Change management and validation

Real safety systems have rigorous change control:
- Dual approval for logic changes
- Extensive testing before deployment
- Safety validation after changes
- Audit trails for all modifications

The simulator doesn't simulate change management processes, safety validation procedures, or the organisational controls around safety systems.

## The observation-only approach

In production environments, safety system testing should be observation-only. The simulator teaches this approach:

### Documentation review

Before touching safety systems, review documentation:
- Safety requirements specification (SRS)
- SIL verification reports
- Cause and effect matrices
- Functional safety assessment reports
- Network architecture diagrams

The simulator could include example safety documentation showing what to look for during assessment.

### Passive network monitoring

Observe safety system traffic without interfering:
- Use passive network tap (not port mirror)
- Capture and analyse traffic offline
- Identify unexpected connections
- Document communication patterns

The simulator could generate realistic safety system traffic patterns for analysis.

### Architecture analysis

Review safety system design from security perspective:
- Is safety system truly independent from production?
- What remote access exists?
- How are updates managed?
- What authentication mechanisms exist?

The simulator demonstrates weak architecture (single safety PLC on shared localhost), showing what not to do.

## What could be added to the simulator

Future enhancements could make safety testing more realistic and educational:

### Redundant safety architecture

Implement SIL-3 style redundancy:
- Two safety PLCs (primary and secondary)
- 2oo3 sensor voting simulation
- Fail-safe logic demonstration
- Redundancy compromise scenarios

Why this would be valuable:
- Demonstrates proper safety system architecture
- Shows why redundancy matters for security
- Teaches assessment of redundant systems
- Illustrates attack complexity against proper design

### Safety system network segmentation

Separate safety network:
- Dedicated network segment for safety PLC
- Firewall rules between production and safety
- One-way data diodes where appropriate
- Scripts to test segmentation effectiveness

Why this would be valuable:
- Shows proper network architecture
- Demonstrates importance of segmentation
- Teaches assessment of network isolation
- Illustrates defence in depth

### Safety authentication and access control

Implement proper access controls:
- Password-protected S7 connections
- Role-based access control simulation
- Change management workflow
- Audit logging of safety system access

Why this would be valuable:
- Demonstrates security best practises
- Shows difference between weak and strong controls
- Teaches assessment of access controls
- Illustrates proper safety system security

### Safety system attack scenarios

Simulation of safety system attacks:
- Scripts that attempt to disable safety interlocks
- Demonstrations of safety threshold manipulation
- Scenarios showing safety system bypass
- Educational content on attack methodologies

With strong warnings:
- These techniques are for educational purposes only
- Never attempt against production safety systems
- Safety system attacks can result in injuries and deaths
- Legal and ethical implications

Why this would be valuable:
- Shows what attackers can do if safety systems lack security
- Demonstrates why safety system security matters
- Teaches defensive strategies
- Motivates proper safety system protection

### Safety vs security trade-off scenarios

Interactive scenarios demonstrating trade-offs:
- Redundancy increases safety but increases attack surface
- Fail-safe design causes denial of service if triggered maliciously
- Simplicity aids safety but limits security features
- Remote access aids rapid response but increases risk

Why this would be valuable:
- Teaches nuanced thinking about safety and security
- Shows why simple answers don't work
- Demonstrates need for balanced approach
- Illustrates real-world decision making

## Ponder's approach to safety testing

Ponder's testing journal included specific guidance on safety system assessment:

"Safety systems require different treatment than production systems. The stakes are too high, the margin for error too small, the relationship with safety engineers too important.

"In the simulator, you can test safety systems more aggressively because there are no physical consequences. Use this freedom to learn proper techniques, not to develop bad habits.

"In production:
1. Always work with safety engineers, never around them
2. Use observation and analysis, not active testing
3. Document findings carefully with safety implications noted
4. Recommend security improvements that enhance or maintain safety

"The simulator demonstrates what weak safety system security looks like. In production, your job is to identify these weaknesses without creating safety incidents.

"Safety always takes precedence over security testing. This isn't negotiable."

## Educational value for different audiences

Safety system security education serves different purposes:

### For security professionals

- How to assess safety systems without interfering with them
- What security weaknesses to look for
- How to communicate findings to safety engineers
- Why safety and security both matter

### For safety engineers

- Why cybersecurity matters for safety systems
- What attackers can do to safety systems
- How security can enhance safety
- What security controls are compatible with safety requirements

### For operations and management

- Why safety system security isn't optional
- What the cost of safety system compromise looks like
- How to balance safety and security requirements
- Why investment in safety system security matters

## Current limitations and future potential

The simulator currently includes a safety PLC that can be tested using existing scripts. This demonstrates basic security weaknesses (lack of authentication, multiple protocol access, information disclosure).

What's missing is the context of proper safety system architecture, the complexity of redundant systems, the reality of safety validation processes, and the organisational controls around safety systems.

Future enhancements could add this context, creating a more realistic and educational safety system testing environment. This would teach not just how to find security weaknesses, but how to assess safety systems comprehensively whilst respecting their critical role.

## The Librarian approach

The Librarian of Unseen University is an orangutan who takes the security of his library very seriously. He has strong opinions about people interfering with his books, and these opinions are backed by approximately 300 pounds of muscle and a tendency toward direct physical communication when annoyed. The key to working in the Library is understanding that whilst the Librarian is responsible for security, you can still conduct research. You just need to do it in ways that don't upset him.

Safety systems should be treated with similar respect. They're critical to facility safety, they're someone else's responsibility (the safety engineer, not the security tester), and interfering with them will result in consequences that are professional rather than physical but no less career-impacting.

The approach that works:

1. Acknowledge that safety takes precedence over security testing
2. Work with the safety team, not around them
3. Use observation and analysis rather than active testing
4. Focus recommendations on "security without compromising safety"

The simulator allows you to test safety systems more aggressively because it's safe to do so. Use this to learn proper assessment techniques and develop respect for safety systems. Then, when working with production safety systems, apply that knowledge with appropriate restraint.

The best safety system test is often the one you don't perform, as long as you can still provide valuable findings through analysis and observation.

---

Further reading:
- [PLC Security](../vulnerabilities/plc.md) - Testing production control systems
- [Network Security](../vulnerabilities/network.md) - Architecture assessment
- [Detection Testing](../exploitation/detection.md) - Monitoring security

For safety system standards and functional safety, consult IEC 61508, IEC 61511, and IEC 62443. The simulator focuses on security implications of safety systems, not functional safety design.
