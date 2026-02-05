# Exploration challenges

*Pick any challenge, in any order, spend as long as you want*

## Challenge 1: Turbine Takeover

The question: Can you remotely control turbine speed?

Why it matters: Turbines are the heart of power generation. Controlling them means controlling the facility.

What you'll learn: Modbus TCP protocol, reading and writing registers, control system manipulation

Where to start:
```bash
# Discover what's listening
python scripts/recon/raw-tcp-probing.py

# Identify Modbus devices
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502

# Understand the turbine
python scripts/recon/turbine_recon.py
```

Make it interesting:
- Can you gradually increase speed without triggering alarms?
- Can you emergency stop all turbines simultaneously?
- Can you make changes that operators won't immediately notice?

Deep dive options:
- How does Modbus actually work? Read the protocol spec
- What other Modbus-controlled systems can you find?
- Can you write your own Modbus attack script?

## Challenge 2: Reactor Secrets

The question: What secrets can you steal from the reactor PLC?

Why it matters: PLC logic is intellectual property. Decades of engineering expertise. Competitors want it. Nation states want it.

What you'll learn: S7comm protocol, PLC memory structure, data exfiltration

Where to start:
```bash
# S7 PLC reconnaissance
python scripts/vulns/s7_plc_status_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Extract PLC logic
python scripts/vulns/s7_readonly_block_dump.py --host 127.0.0.1 --port 102 --rack 0 --slot 2

# Read memory
python scripts/vulns/s7_read_memory.py --host 127.0.0.1 --port 102 --rack 0 --slot 2
```

Make it interesting:
- What information is exposed in the PLC status?
- Can you extract complete control programmes?
- How would a competitor use this information?

Deep dive options:
- Understand S7 addressing (rack, slot, DB blocks)
- What's different about the safety PLC (port 103)?
- Can you modify PLC logic, not just read it?

## Challenge 3: SCADA Surveillance

The question: What can you see in the SCADA system?

Why it matters: SCADA is the eyes and ears of the facility. Complete operational visibility.

What you'll learn: OPC UA protocol, tag enumeration, data access

Where to start:
```bash
# OPC UA reconnaissance
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Try the backup SCADA too
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4841
```

Make it interesting:
- Is anonymous access allowed?
- What operational data is visible?
- Can you monitor in real-time?

Deep dive options:
- How does OPC UA security work (when it's enabled)?
- What's the difference between primary and backup SCADA?
- Can you write to SCADA tags, not just read?

## Challenge 4: Multi-Protocol Mastery

The question: How many different ways can you access the same system?

Why it matters: Defence in depth fails when every protocol is vulnerable.

What you'll learn: EtherNet/IP, protocol comparison, redundant access paths

Where to start:
```bash
# The turbines speak multiple protocols
# Try Modbus (port 10502)
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502

# Try EtherNet/IP (port 44818)
python scripts/vulns/ab_logix_tag_inventory.py --host 127.0.0.1 --port 44818
```

Make it interesting:
- Can you access the same data via different protocols?
- Which protocol gives you more information?
- If one protocol was secured, could you use another?

Deep dive options:
- Why do industrial devices support multiple protocols?
- What's the difference between Modbus and EtherNet/IP?
- Can you pivot between protocols?

## Challenge 5: The Complete Picture

The question: Can you map the entire facility?

Why it matters: Attack planning requires understanding the full landscape.

What you'll learn: Network architecture, system relationships, comprehensive reconnaissance

Where to start:
```bash
# Start with port discovery
python scripts/recon/raw-tcp-probing.py

# Then enumerate each protocol
# (Use scripts from previous challenges)
```

Make it interesting:
- Create a network diagram showing all systems
- Map which systems control what
- Identify the most critical targets
- Find unexpected connections

Deep dive options:
- How would you prioritise targets for attack?
- What's the difference between production and safety systems?
- If you could only attack one system, which would cause most impact?

## Challenge 6: Stealth and Detection

The question: Can you operate without being detected?

Why it matters: Real attackers try to avoid detection. So do sophisticated pentesters.

What you'll learn: Traffic analysis, rate limiting, evasion techniques

Where to start:
```bash
# Compare obvious vs stealthy scanning
# Fast and obvious:
python scripts/recon/raw-tcp-probing.py

# Slow and subtle:
python scripts/exploitation/anomaly_bypass_test.py --scan-delay 300

# Traffic camouflage:
python scripts/exploitation/protocol_camouflage.py --mimic-hmi
```

Make it interesting:
- How slow do you need to be to avoid detection?
- Can you mimic legitimate traffic?
- What would monitoring systems see?

Deep dive options:
- What would good detection look like?
- How would you design IDS rules for industrial protocols?
- Can you pivot through legitimate systems?

## Challenge 7: Maximum impact

The question: What's the most dramatic thing you can demonstrate?

Why it matters: Sometimes you need to prove impact to get resources for fixes.

What you'll learn: Attack chains, combining vulnerabilities, PoC development

Where to start:
```bash
# Try the pre-built attacks
python scripts/exploitation/turbine_overspeed_attack.py --host 127.0.0.1 --port 10502 --target-speed 1600
python scripts/exploitation/turbine_emergency_stop.py --host 127.0.0.1 --port 10502
```

Make it interesting:
- Can you affect multiple systems simultaneously?
- What's the worst-case scenario you can demonstrate?
- Can you create a cascading failure?

Deep dive options:
- How would you demonstrate this to non-technical executives?
- Video evidence or live demo?
- What would operations see when this happens?

## Challenge 8: Your own adventure

The question: What interests you?

Why it matters: Best learning follows curiosity.

Create your own challenge:
- Something you noticed that wasn't covered
- A question about how something works
- An attack idea you want to test
- A hypothesis to prove or disprove

Discuss with facilitators and see where it leads.

## Challenge 9: Fix it (if you want)

The question: If you found these vulnerabilities, what would you actually fix?

Why it matters: Understanding remediation helps you think like both attacker and defender.

What you'll explore:
- Which vulnerabilities matter most?
- What's actually fixable vs what's not?
- How would you prioritise fixes?
- What would the implementation look like?

Approach it however you want:
- Technical: Design network segmentation, write firewall rules, configure authentication
- Strategic: Prioritise findings by risk and feasibility
- Creative: Find solutions that work within constraints
- Curious: Research how real facilities handle these issues

Make it interesting:
- Pick your top 3 vulnerabilities and propose fixes
- Design a complete security architecture
- Consider what can't be fixed and why
- Compare quick wins vs long-term solutions

Deep dive options:
- Study IEC 62443 zone and conduit model
- Research real OT security implementations
- Design monitoring and detection systems
- Consider cost, downtime, and operational impact

Only do this if remediation interests you. Many students prefer staying in attack mode all day, and that's fine.

---

*"The presence of those seeking the truth is infinitely to be preferred to the presence of those who think they've found it." - Terry Pratchett*
