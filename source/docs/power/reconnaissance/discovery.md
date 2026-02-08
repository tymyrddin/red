# Discovery

*Extract from the Field Notes of Ponder Stibbons*

The [active reconnaissance](active.md) had answered "what is there?" Now came the question "what can we learn from it?" This was discovery: the systematic, methodical enumeration of memory maps, register ranges, and the detailed structure of control systems.

Where reconnaissance asks polite questions, discovery reads the entire manual. Where reconnaissance confirms presence, discovery maps extent. This is deep enumeration, patient, thorough, and revealing.

## The first question

With port `10502` confirmed as a responsive Modbus endpoint, the immediate question was: what else responds? The [passive map](passive.md) showed sustained traffic on ports `10502` through `10506`, moderate traffic on `10520`, and sporadic traffic on `10510`. Were all of these Modbus? Did they respond to the same unit IDs?

The script [`scan_unit_ids.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/scan_unit_ids.py) performs a systematic sweep:

```bash
$ python scripts/discovery/scan_unit_ids.py
[*] Scanning for responsive Modbus unit IDs across discovered ports...

Port 10502:
  Unit ID 1: RESPONDS ✓
  Unit ID 2: RESPONDS ✓
  Unit ID 3: RESPONDS ✓
  (All tested unit IDs respond - simulator accepts any ID)

Port 10503:
  Unit ID 1: RESPONDS ✓
  (Pattern repeats across ports)

[!] Simulator Anomaly: All unit IDs respond on all ports
[*] Real PLCs would reject invalid unit IDs with exception code 0x0B
[*] This confirms simulator environment, not production hardware
```

This revealed a simulator limitation. In operational systems, each Modbus device has a configured unit ID and rejects queries with incorrect IDs. Here, every unit ID worked on every port. This was unrealistic but useful, it confirmed we were working with a forgiving test environment, not fragile production equipment.

The script saved detailed results to `reports/unit_id_scan_*.json` documenting which IDs responded on which ports.

## Memory mapping

With connectivity confirmed, the next step was understanding the memory layout. Modbus devices expose four address spaces:
- Coils: Binary outputs (read/write)
- Discrete Inputs: Binary inputs (read-only)
- Input Registers: 16-bit analogue inputs (read-only)
- Holding Registers: 16-bit analogue outputs (read/write)

Each address space could potentially hold thousands of registers. Testing every address would be time-consuming and generate suspicious traffic. The approach needed to be strategic: test key addresses, identify patterns, map boundaries.

The script [`modbus_memory_census.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/modbus_memory_census.py) reads strategic blocks:

```bash
$ python scripts/discovery/modbus_memory_census.py
[*] Modbus Memory Map Census
[*] Target: 127.0.0.1:10502

[*] Scanning Holding Registers (Function Code 03)...
  Address 0: 1500 (Speed setpoint)
  Address 1: 0 (Power setpoint)
  Addresses 2-9: [0, 0, 0, 0, 0, 0, 0, 0]
  Addresses 10+: Exception 0x02 (Illegal Data Address)

[*] Holding Register range: 0-1 (2 registers)

[*] Scanning Input Registers (Function Code 04)...
  Address 0: 1503 (Current speed)
  Address 1: 15 (Current power)
  Address 2: 45 (Bearing temp)
  Address 3: 8 (Oil pressure)
  Address 4: 2 (Vibration)
  Address 5: 62 (Generator temp)
  Address 6: 58 (Gearbox temp)
  Address 7: 22 (Ambient temp)
  Address 8: 0
  Address 9: 0
  Addresses 10+: Exception 0x02 (Illegal Data Address)

[*] Input Register range: 0-9 (10 registers, 8 active)

[*] Scanning Coils (Function Code 01)...
  Address 0: True (Control mode AUTO)
  Address 1: False (E-stop inactive)
  Address 2: False (Maintenance mode off)
  Addresses 3+: Exception 0x02 (Illegal Data Address)

[*] Coil range: 0-2 (3 coils)

[*] Scanning Discrete Inputs (Function Code 02)...
  Address 0: False (Overspeed OK)
  Address 1: False (Oil pressure OK)
  Address 2: False (Bearing temp OK)
  Address 3: False (Vibration OK)
  Address 4: False (Generator fault OK)
  Addresses 5-7: False
  Addresses 8+: Exception 0x02 (Illegal Data Address)

[*] Discrete Input range: 0-7 (8 inputs, 5 active alarms)

[*] Memory census complete
[*] Total accessible addresses: 23
[*] PLC has a compact, well-defined memory map
```

This revealed a deliberately constrained memory layout. Only 23 accessible addresses across all four spaces. This was intentional design, the simulator modelled specific turbine telemetry, not a general-purpose PLC with thousands of I/O points.

The compact map made comprehensive testing feasible. With only 23 addresses, every one could be monitored without generating excessive traffic.

## Input register deep dive

Input registers held sensor readings, the live telemetry from the turbine. Understanding these values required watching them change over time. Were they static? Random? Physically realistic?

The script [`check_input_registers.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/check_input_registers.py) samples registers repeatedly:

```bash
$ python scripts/discovery/check_input_registers.py
[*] Input Register Discovery - Repeated sampling
[*] Target: 127.0.0.1:10502

Sample 1 (T+0s):   [1502, 15, 45, 8, 2, 62, 58, 22, 0, 0]
Sample 2 (T+5s):   [1503, 15, 45, 8, 2, 62, 58, 22, 0, 0]
Sample 3 (T+10s):  [1501, 16, 45, 8, 2, 63, 58, 22, 0, 0]
Sample 4 (T+15s):  [1502, 15, 46, 8, 2, 62, 59, 22, 0, 0]
Sample 5 (T+20s):  [1500, 15, 45, 8, 2, 62, 58, 22, 0, 0]

[*] Analysis:
  IR 0 (Speed): Oscillates ±3 RPM around 1500 (realistic control variance)
  IR 1 (Power): Stable at 15 MW (consistent output)
  IR 2 (Bearing temp): 45-46°C (minor thermal fluctuation)
  IR 3-4: Stable (oil pressure, vibration within normal range)
  IR 5-6 (Temps): 62-63°C, 58-59°C (realistic thermal behavior)
  IR 7 (Ambient): Constant 22°C (simulated environment)
  IR 8-9: Always zero (unused addresses)

[*] Conclusion: Values show realistic physics simulation
[*] Not random, not static - genuine control system behavior
```

The values oscillated realistically. Speed varied by ±3 RPM around the setpoint, normal for a control loop with real-world disturbances. Temperatures drifted by 1-2 degrees, thermal inertia creating lag. This wasn't a crude simulator returning random numbers. It was implementing physics.

## Write permission testing

Discovery includes identifying what can be modified. Holding registers are theoretically read/write, but some PLCs protect certain registers or require authentication. Testing write access needed to be non-destructive.

The script [`test_write_permissions.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/test_write_permissions.py) performs the safest possible test: read current value, write same value back, verify unchanged:

```bash
$ python scripts/discovery/test_write_permissions.py
[*] Testing Write Permissions (non-destructive)
[*] Target: 127.0.0.1:10502

[*] Test: Holding Register 0 (Speed Setpoint)
  Current value: 1500 RPM
  Writing same value back (1500)...
  Write accepted ✓
  Verification read: 1500 RPM
  No change observed ✓

[*] Test: Holding Register 1 (Power Setpoint)
  Current value: 0 MW
  Writing same value back (0)...
  Write accepted ✓
  Verification read: 0 MW
  No change observed ✓

[*] Conclusion: Holding registers are writable without authentication
[*] No write protection observed
[*] Exercise extreme caution with any write operations
```

Both holding registers accepted writes without authentication or confirmation. This was the open door for [exploitation](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation). An attacker with network access could modify setpoints directly. No password required. No audit trail. No confirmation prompt.

This lack of authentication is distressingly common in real industrial systems. Modbus was designed for closed, trusted networks where physical access implied authorisation. Its transplant to TCP/IP networks retained this assumption while removing the physical security.

## The comprehensive discovery scripts

Beyond the core memory mapping, additional discovery scripts revealed finer details:

[`compare_unit_id_memory.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/compare_unit_id_memory.py) - Compared memory contents across unit IDs, confirming they all returned identical data (simulator artefact).

[`decode_register_0_type.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/decode_register_0_type.py) - Tested whether register 0 stored a 16-bit integer, 32-bit integer, or floating-point value. Confirmed 16-bit unsigned integer (range 0-65535).

[`sparse_modbus_scan.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/sparse_modbus_scan.py) - Probed strategic addresses (0, 100, 1000, 2000, etc.) looking for extended memory regions. Found only the documented 0-9 range was implemented.

[`check_discrete_points.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/check_discrete_points.py) - Enumerated all coils and discrete inputs, confirming the compact 3-coil, 8-discrete-input layout.

[`poll_register_0.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/discovery/poll_register_0.py) - Monitored register 0 over extended periods, observing the ±3 RPM oscillation pattern and confirming the PID control loop behaviour.

These scripts, available in the [`scripts/discovery`](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/discovery) directory, represent the systematic approach to enumeration: test assumptions, document findings, identify boundaries, understand behaviour.

## The detailed map

Discovery produced a complete memory map of the turbine PLC:

Holding Registers (Read/Write Setpoints):
```
0: Speed Setpoint (1500 RPM default)
1: Power Output Setpoint (0 MW default)
```

Input Registers (Read-Only Telemetry):
```
0: Current Speed (RPM, oscillates ±3 around setpoint)
1: Current Power Output (MW)
2: Bearing Temperature (°C)
3: Oil Pressure (bar)
4: Vibration Level (mm/s)
5: Generator Temperature (°C)
6: Gearbox Temperature (°C)
7: Ambient Temperature (°C)
8-9: Unused (always 0)
```

Coils (Read/Write Control Flags):
```
0: Control Mode (0=Manual, 1=Auto)
1: Emergency Stop (0=Normal, 1=Stopped)
2: Maintenance Mode (0=Off, 1=On)
```

Discrete Inputs (Read-Only Alarm States):
```
0: Overspeed Alarm (0=OK, 1=Alarm)
1: Low Oil Pressure (0=OK, 1=Alarm)
2: High Bearing Temperature (0=OK, 1=Alarm)
3: High Vibration (0=OK, 1=Alarm)
4: Generator Fault (0=OK, 1=Alarm)
5-7: Unused (always 0)
```

This map was now documented, tested, and verified. Every address had been read. Write permissions had been confirmed. 
Value ranges and behaviours were understood. The simulator's internal structure was no longer opaque.

## The simulator's transparency

Discovery revealed that the simulator was remarkably honest. It didn't hide functionality. It didn't require credentials. It didn't rate-limit queries. It responded to every valid request with accurate data.

This transparency served the simulator's purpose: to be a realistic test environment for security research. Real PLCs often have similar openness, industrial protocols prioritise reliability and real-time response over security. Modbus has no authentication. S7comm's password protection is trivially bypassed. EtherNet/IP has minimal access control.

The simulator faithfully replicated this vulnerable-by-design architecture.

## The foundation for exploitation

Discovery provides the knowledge required for [exploitation](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation). We now knew:
- Which registers controlled turbine behaviour (HR 0-1)
- Which registers monitored turbine state (IR 0-7)
- Which addresses were writable without authentication (HR 0-1, all coils)
- How values behaved over time (realistic physics simulation)
- What alarm conditions existed (DI 0-4)

An attacker with this map could craft precise attacks: write to HR 0 to change speed setpoint, monitor IR 0 to observe the effect, watch DI 0 to detect overspeed alarms, write to coil 1 to trigger emergency stops.

Discovery is reconnaissance made comprehensive. It's the detailed blueprint that transforms "something is there" into "here is exactly how it works and what it does."

This knowledge, documented across 18 discovery scripts in the repository, represented days of careful enumeration. But in an operational attack, this discovery phase might take hours. Automated tools can enumerate Modbus memory rapidly. The simulator's compact address space could be fully mapped in minutes.

The lesson: discovery is not time-consuming if you're systematic. And once complete, it provides everything needed for the next phase.

## The architectural understanding

Beyond individual registers, discovery revealed the system architecture. The simulator implemented:

- Three turbine PLCs (ports 10502-10504) with identical memory maps, representing redundant turbines in the power generation facility.
- A safety PLC (port 10503) with the same interface but different physical context (safety interlocks rather than operational control).
- A SCADA gateway (port 10520) that aggregated data from field devices, providing centralised monitoring and control.
- Additional devices (ports 10505-10506, 10510) with variations on the core architecture, representing pumps, cooling systems, or other auxiliary equipment.

This wasn't just a single PLC simulation. It was a facility simulation with multiple control domains, realistic device relationships, and operational dependencies. Discovery of one device informed understanding of others,the architectural patterns repeated across the environment.

## The transition point

Discovery bridges reconnaissance and exploitation. [Active reconnaissance](active.md) identified targets. Discovery mapped their internals. Now came the question: what happens if we modify what we discovered?

That question leads to [exploitation scripts](https://github.com/tymyrddin/power-and-light-sim/tree/main/scripts/exploitation), where discovery becomes demonstration, where knowledge becomes capability, and where the Patrician's directive shifts from "learn about it" to "show us what an attacker could do."

But that, as with all dangerous demonstrations, requires its own careful documentation and explicit permission.

Discovery was complete. The maps were drawn. The registers were known. The simulator had revealed its internals.

Now came the work of showing what could be done with that knowledge,responsibly, documentedly, and with the safety of a simulator rather than the risk of production systems.

The next phase would be... interesting.
