# Technical tips for exploration

*Practical guidance for hacking industrial control systems*

## Getting started

### Setup

Have it installed on your machine, or install it at another machine (and then adapt the IP adresses in the hacking scripts)

Start the simulator:
```bash
python tools/simulator_manager.py
```

Test that it's working in a separate terminal or other machine:
```bash
python scripts/recon/raw-tcp-probing.py
```

You should see ports listening: 102, 103, 4840, 4841, 10501-10504, 44818-44820.

### Choose your approach

Solo: Work independently, go at your own pace.

Small group (2-4 people): Collaborate on challenges, share discoveries.

Hybrid: Start solo, join others when you want, split up when you prefer independence.

You can change your mind anytime.

### Pick a challenge

See [Exploration challenges](challenges.md) for ideas.

Recommended starting points:
- New to industrial security? Start with Challenge 1 (Turbine Takeover) - Modbus is simplest
- Like puzzles? Try Challenge 5 (Complete Picture) - map everything
- Want drama? Try Challenge 7 (Maximum Impact) - make things crash

Just pick one and start exploring.

## Using the scripts

### Read the code first

Don't just run scripts blindly:

```bash
# See what it does
cat scripts/recon/modbus_identity_probe.py
```

Understanding the code teaches you:
- How the protocol works
- What requests are sent
- What responses mean
- How to modify it

### Experiment with parameters

Try different options:

```bash
# Different ports
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10502
python scripts/recon/modbus_identity_probe.py --host 127.0.0.1 --port 10503

# Different parameters
python scripts/exploitation/turbine_overspeed_attack.py --target-speed 1600
python scripts/exploitation/turbine_overspeed_attack.py --target-speed 2000 --step-size 5
```

See what works. See what breaks.

### Document your discoveries

Keep notes:
- Commands that worked
- Interesting outputs
- Questions that came up
- What you discovered

Take screenshots of interesting findings. Record videos of attacks working.

## Exploration strategies

### Strategy 1: Protocol-focused

[Pick a protocol](protocol-reference.md) (Modbus, S7, OPC UA, EtherNet/IP) and master it:
- Understand how it works
- Try all scripts for that protocol
- Read protocol specification
- Write your own client
- Capture and analyse traffic

### Strategy 2: System-focused

Pick one system (turbine, reactor, SCADA) and explore everything about it:
- What protocols does it support?
- What data is accessible?
- What can you control?
- How does it respond to attacks?

### Strategy 3: Attack-focused

[Pick an attack goal](challenges.md) and achieve it:
- Control turbine speed remotely
- Extract all PLC logic
- Map complete facility architecture
- Create cascading failures

### Strategy 4: Breadth-first

Try a bit of everything:
- Test each protocol quickly
- Move between systems
- Get overview of entire attack surface
- Then go deep on what interests you

No "right" strategy. Follow your curiosity.

## Going deeper

### Write your own scripts

Modify existing scripts or create new ones:

```python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('127.0.0.1', port=10502)
client.connect()

# Read holding registers
result = client.read_holding_registers(address=0, count=10, slave=1)
print(result.registers)

client.close()
```

### Analyse network traffic

Use Wireshark to see what's happening:

```bash
# Capture traffic
sudo tcpdump -i lo -w capture.pcap port 502

# Then analyse in Wireshark
wireshark capture.pcap
```

Look for:
- Protocol structure
- Commands and responses
- Authentication (or lack thereof)
- Data being transmitted

### Chain attacks

Combine multiple vulnerabilities:
- Reconnaissance → Exploitation → Impact
- Multiple protocols against same target
- Simultaneous attacks on different systems

Example:
1. Enumerate turbine via Modbus
2. Access same turbine via EtherNet/IP
3. Extract SCADA data via OPC UA
4. Correlate information
5. Demonstrate coordinated attack

### Attack defensive measures

If the facility had security, how would you bypass it:
- Slow scanning to avoid rate limits
- Traffic camouflage to look legitimate
- Protocol-specific evasion techniques

Scripts for this:
```bash
python scripts/exploitation/anomaly_bypass_test.py --scan-delay 300
python scripts/exploitation/protocol_camouflage.py --mimic-hmi
```

## When things go wrong

### Simulator issues

Simulator won't start:
```bash
# Check if already running
ps aux | grep simulator

# Kill and restart
pkill -f simulator_manager
python tools/simulator_manager.py
```

Ports not listening:
```bash
# Check what's listening
ss -tlnp | grep -E ":(4840|102|502|44818)"
```

If nothing: simulator isn't running. Start it.

### Script issues

Import errors:
```bash
pip install -r requirements.txt
```

Connection refused:
- Is simulator running?
- Correct port number?
- Correct host (127.0.0.1)?

Timeouts:
- Some operations take time
- Try increasing timeout in script
- Check if target system is responsive

No data returned:
- Might be normal for some queries
- Try different address ranges
- Check script output for errors

### Getting stuck

If stuck after 10-15 minutes:
1. Try a different script
2. Try a different protocol/system
3. Ask another student
4. Ask facilitator

Don't waste time being stuck. Get help.

### Common mistakes

Wrong port numbers:
- Modbus: 10501-10504
- S7: 102-103
- OPC UA: 4840-4841
- EtherNet/IP: 44818-44820

Wrong S7 parameters:
- Usually rack 0, slot 2 or 3
- Try both if one doesn't work

Not reading script output:
- Errors tell you what's wrong
- Read them carefully

## Taking breaks

When to take a break:
- Feeling frustrated
- Can't solve a problem
- Eyes getting tired
- Need to think

Breaks are productive. Your brain processes while you rest.

Grab coffee, chat with others, take a walk. Come back fresh.

## End of day

Reflect on:
- What did you discover?
- What surprised you?
- What was hardest?
- What was most fun?
- What do you want to explore more?

Share with others. Their discoveries add to your learning.

## After the workshop

### Keep exploring

The simulator is yours:
```bash
python tools/simulator_manager.py
```

Continue trying challenges. Go deeper. Write your own tools.

### Learn more

Technical depth:
- Protocol specifications (Modbus, S7, OPC UA, EtherNet/IP)
- IEC 62443 standards
- Real attack case studies (Stuxnet, Triton, Ukraine grid)

Practical skills:
- SANS ICS courses (ICS410, ICS515)
- Contribute to open-source ICS tools
- Build your own lab environment
- Practice on other simulators

Career paths:
- OT security consultant
- ICS penetration tester
- Industrial security researcher
- Critical infrastructure protection

### Resources

Documentation:
- Protocol specs online
- IEC 62443 series
- NIST Cybersecurity Framework
- ICS-CERT advisories

Communities:
- r/ICS on Reddit
- ICS security conferences (S4, ICS Summit)
- Local security meetups
- Open-source ICS projects

Tools:
- Nmap with NSE scripts for ICS
- Metasploit ICS modules
- Custom Python scripts
- Wireshark with ICS dissectors

---

*"The best way to learn is by breaking things. Safely." - Ponder Stibbons*

*Keep exploring. Keep learning. Keep breaking things (in the simulator).*
