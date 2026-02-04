# PLC security testing: Overly trusting controllers

![PLCs](/_static/images/ot-plcs.png)

*Or: How Ponder Discovered That Industrial Controllers Were Designed For A Simpler Time*

## The heart of the problem

Programmable Logic Controllers, Ponder noted in his testing journal, were marvels of engineering. They read sensors, executed logic, controlled actuators, and did it all in milliseconds, reliably, for decades. The turbine PLC at UU Power & Light had been running continuously since 1998, which was longer than most of the current staff had been employed.

They were also, he discovered, completely insecure.

This wasn't incompetence on the part of PLC manufacturers. When these devices were designed, security simply wasn't part of the specification. PLCs were meant to sit in locked control rooms, on isolated networks, programmed only by trusted engineers with physical access. The security model was straightforward: if you could reach the PLC on the network, you were authorised to be there.

That assumption, Ponder reflected whilst staring at the simulator's network traffic, was now catastrophically wrong. But the PLCs remained, and someone had to test whether they could be secured. Or at least understand exactly how insecure they were.

## Testing the reactor PLC: S7 Protocol

The UU P&L simulator included a Siemens S7-400 PLC controlling the alchemical reactor. Ponder started with the most basic question: would it respond at all?

### First contact

The first test was simply attempting to connect. Using [Snap7](http://snap7.sourceforge.net/), a free open-source library for S7 communication, Ponder wrote a simple [connection test](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/testing-turbine-control-plcs.py).

```python
# From testing-turbine-control-plcs.py
plc = snap7.client.Client()
plc.connect('127.0.0.1', 0, 2)  # IP, rack, slot
```

The PLC responded immediately. No password prompt. No authentication challenge. No "are you quite sure you should be doing this?" dialogue. It simply accepted the connection and waited for commands.

"That's... concerning," Ponder muttered, making a note in his journal.

### Extracting status information

Once connected, Ponder tried requesting status information with a [status dump script](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_plc_status_dump.py). The PLC cheerfully provided:
- CPU type and firmware version
- Current operational state (RUN/STOP/MAINT)
- System diagnostics
- Memory usage statistics

All without authentication. The PLC's attitude seemed to be that if you could ask the question, you were entitled to the answer.

Security implication: An attacker now knows exactly what PLC model and firmware version is present. This information is invaluable for selecting appropriate exploits or understanding system capabilities.

### Reading memory

The next test was [reading memory areas](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_read_memory.py). S7 PLCs have several memory regions:
- Process Image Input (PI/PA): Sensor values
- Process Image Output (PO/PE): Actuator states
- Data Blocks (DB): Structured configuration data
- Flags (M): Internal calculation memory

```python
# From s7_read_memory.py
# Read process inputs
data = plc.read_area(snap7.types.S7AreaPA, 0, 0, 100)

# Read process outputs
data = plc.read_area(snap7.types.S7AreaPE, 0, 0, 100)

# Read data blocks
data = plc.read_area(snap7.types.S7AreaDB, 1, 0, 100)
```

The PLC provided complete access to all memory areas. Ponder could observe real-time reactor temperatures, valve positions, setpoints, and control parameters. It was like having a window directly into the control system's brain, with no curtains.

Security implication: Complete visibility into operational state. An attacker can observe system behaviour, identify control patterns, and plan precise attacks based on actual operating conditions.

### Downloading the programme

The most significant test was [downloading programme blocks](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/s7_readonly_block_dump.py) from the PLC.

S7 programmes are organised into blocks:
- OB (Organisation Blocks): Main programme logic
- FC (Functions): Reusable subroutines
- FB (Function Blocks): Stateful logic modules
- DB (Data Blocks): Structured data storage

```python
# From s7_readonly_block_dump.py
for block_type in ['OB', 'FC', 'FB', 'DB']:
    for block_num in range(1, 100):
        try:
            block_data = plc.upload(block_num)
            # Save to reports/s7_blocks/
        except:
            continue
```

The PLC uploaded its entire programme without complaint. Ponder now had complete access to the reactor control logic, including startup sequences, safety interlocks, alarm conditions, and control algorithms.

One comment in the downloaded code (in German, because Siemens) translated to: "TODO: Add proper input validation here - currently assumes sensors always return valid values." Another simply read "Works on my machine", which was not particularly reassuring in code controlling an alchemical reactor.

Security implication: Complete intellectual property theft and reverse engineering capability. An attacker with programme blocks can understand exactly how the system works, identify weaknesses in control logic, and craft precision attacks. This also represents theft of proprietary control algorithms.

### Password "protection"

The simulator's reactor safety PLC had password protection enabled. Ponder tested this with a 
[brute force demonstration](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/plc_password_bruteforce.py).

The password was four digits. Four digits means 10,000 possible combinations. The script (in simulated mode, for educational purposes) demonstrated that such passwords could be brute forced in minutes.

The actual password, when eventually found, was `1234`. Which was simultaneously predictable and depressing.

Security implication: Weak password protection provides false confidence. Four-digit numeric passwords offer no meaningful security against automated attacks.

Important note: The script runs in simulated mode for educational demonstration. Testing password attacks against production systems is not recommended (it takes time, generates traffic, and may trigger lockouts or alarms).

## Testing the turbine PLC: Modbus protocol

The turbine controller also supported Modbus TCP, a universal industrial protocol. Modbus has the advantage (from an attacker's perspective) of being even simpler than S7.

### Reading everything

Ponder's first Modbus test was a [complete memory snapshot](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/modbus_coil_register_snapshot.py). Modbus organises memory into:
- Coils: Discrete outputs (ON/OFF controls)
- Discrete Inputs: Discrete inputs (ON/OFF sensors)
- Input Registers: Analogue sensor values (read-only)
- Holding Registers: Analogue setpoints and parameters (read/write)

```python
# From modbus_coil_register_snapshot.py
client = ModbusTcpClient(host="127.0.0.1", port=10502)
client.connect()
client.slave_id = 1

# Read everything
coils = client.read_coils(address=0, count=10)
discrete_inputs = client.read_discrete_inputs(address=0, count=10)
input_registers = client.read_input_registers(address=0, count=10)
holding_registers = client.read_holding_registers(address=0, count=10)
```

The PLC provided complete access. No authentication. No "read-only mode" restrictions. Every coil, every register, every sensor value, all available to anyone who could reach port 10502.

The script saved the complete snapshot to `reports/modbus_snapshot_<timestamp>.json`, creating a perfect record of the turbine's operational state at that moment.

Security implication: Modbus TCP has no authentication mechanism. The protocol operates on the principle that network access equals authorisation. If you can reach the port, you can read everything.

### The write problem

Whilst Ponder's testing focused on read-only reconnaissance (safer, and sufficient to demonstrate the vulnerabilities), Modbus also supports write operations:
- Function Code 05: Write Single Coil (turn output ON/OFF)
- Function Code 06: Write Single Register (change setpoint)
- Function Code 15: Write Multiple Coils
- Function Code 16: Write Multiple Registers

These functions allow direct control of the physical process. An attacker with network access could:
- Force turbine outputs (valves, motors, controls)
- Change setpoints (speed targets, temperature limits)
- Modify operational parameters

No authentication required. Just send the right bytes to the right port.

Security implication: Modbus write operations allow complete control without authentication. This is not a vulnerability in Modbus (it was never designed for untrusted networks), but it is a significant security concern when Modbus PLCs are accessible.

## Testing Allen-Bradley controllers: EtherNet/IP

The turbine PLC also implemented EtherNet/IP (Common Industrial Protocol), used by Allen-Bradley ControlLogix systems. This protocol uses tag-based addressing rather than numeric registers.

### Tag enumeration

Ponder's [tag inventory script](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/ab_logix_tag_inventory.py) connected to the EtherNet/IP server and requested a complete tag list.

```python
# Simplified mode for simulator
sock.connect(('127.0.0.1', 44818))
# Send Register Session request
# Receive tag list
```

The controller provided 18 tags with complete metadata:

```
SpeedSetpoint         DINT    [R/W]  ← Writable control point
PowerSetpoint         DINT    [R/W]  ← Writable control point
CurrentSpeed          DINT    [R/O]
CurrentPower          DINT    [R/O]
BearingTemp           INT     [R/O]
EmergencyStop         BOOL    [R/W]  ← Critical control
OverspeedAlarm        BOOL    [R/O]
...
```

The tag list helpfully identified which tags were writable. From an attacker's perspective, this was exactly the information needed: which control points could be modified, and what their names were.

Security implication: Complete mapping of control points and their access permissions. An attacker now knows exactly which tags control the turbine and which are merely monitoring values. The R/W tags are, obviously, the interesting ones.

## What the testing revealed

After several days of testing the simulator's PLCs, Ponder's conclusions were uncomfortable:

### No authentication by default

None of the protocols (S7, Modbus TCP, EtherNet/IP) required authentication in their default configurations. The security model was "network isolation provides security", which worked when PLCs were genuinely isolated but fails catastrophically when networks are interconnected.

### Complete information disclosure

All three protocols allowed complete enumeration of:
- Device type and firmware versions
- Control programme logic (S7)
- Tag/register mappings
- Current operational state
- Configuration parameters

This information enables reconnaissance for targeted attacks.

### Read access enables write attacks

Even "harmless" read-only access provides the intelligence needed for effective attacks. Understanding how a system operates, what its setpoints are, and how it responds to conditions is the prerequisite for disrupting it effectively.

### No intrinsic security mechanisms

The protocols themselves have no security features. S7 has optional password protection (weak). Modbus has none. EtherNet/IP has none. Security must be provided by external controls (network segmentation, firewalls, access control), not by the protocols themselves.

## The simulator as a teaching tool

Testing the UU P&L simulator provided a safe environment to understand these vulnerabilities without risking actual equipment. Every test was read-only reconnaissance (except the simulated brute force), demonstrating what attackers could observe and learn about industrial systems.

The scripts in `scripts/vulns/` provide:
- Hands-on experience with industrial protocols
- Understanding of what authentication weaknesses look like
- Practical knowledge of information disclosure risks
- Foundation for understanding attack vectors

Important notes for using these scripts:

S7 protocols (port 102) require elevated privileges:
```bash
sudo .venv/bin/python scripts/vulns/s7_plc_status_dump.py
sudo .venv/bin/python scripts/vulns/s7_read_memory.py
sudo .venv/bin/python scripts/vulns/s7_readonly_block_dump.py
sudo .venv/bin/python scripts/vulns/testing-turbine-control-plcs.py
```

Modbus and EtherNet/IP run as regular user:
```bash
python scripts/vulns/modbus_coil_register_snapshot.py
python scripts/vulns/ab_logix_tag_inventory.py
```

All scripts save results to `reports/` directory for analysis.

## The uncomfortable reality

PLCs were never designed to be secure. They were designed to be reliable, real-time, and deterministic. Security was meant to be provided by physical access control and network isolation.

Those controls have eroded. PLCs are now on networks that connect to corporate IT, to remote access systems, occasionally to the Internet. The assumption that "if you can reach the PLC, you're authorised" is no longer valid.

Yet the PLCs remain, running critical infrastructure, often irreplaceable, and completely insecure by modern standards. At UU P&L, every PLC tested had critical security weaknesses. None could be fixed without replacement, and replacement wasn't an option for equipment costing hundreds of thousands of pounds and requiring months of downtime.

The only realistic security measures are compensating controls:
- Network segmentation to limit who can reach PLCs
- Network monitoring to detect unauthorised access attempts
- Application whitelisting on systems that connect to PLCs
- Accepting the residual risk that PLCs themselves cannot be made secure

This is the reality of OT security that the simulator demonstrates. The devices themselves are insecure and will remain so. Security must be built around them, not in them.

The PLCs at real facilities like UU P&L will continue running, insecure, for years or decades more. The security team's job is to ensure that reaching those PLCs is as difficult as possible, and that unauthorised access is detected quickly.

Perfect security isn't possible. Adequate security through defence in depth is achievable, even if imperfect and requiring constant vigilance.

Ponder closed his testing journal and made one final note: "The PLCs trust anyone who can speak their language. Unfortunately, learning industrial protocols is not particularly difficult, and the protocols themselves are well-documented. This is not a vulnerability that can be patched. It is the fundamental design."

Further Reading:

- [Vulnerability Assessment Scripts](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/README.md) - Technical details on all PLC testing scripts
- [TESTING_CHECKLIST](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/TESTING_CHECKLIST.md) - Complete test coverage
- [SIMULATOR_GAPS](https://github.com/ninabarzh/power-and-light-sim/tree/main/SIMULATOR_GAPS.md) - Known limitations

The scripts demonstrate real-world attack vectors against industrial controllers. All tests are read-only reconnaissance (except simulated authentication testing) but demonstrate the foundation for understanding PLC vulnerabilities.
