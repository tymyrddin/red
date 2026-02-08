# Active reconnaissance

*Extract from the Field Notes of Ponder Stibbons*

The [passive capture](passive.md) had revealed the landscape. Ports `10502` through `10520` were the stage. Now came 
the delicate work of stepping onto that stage without breaking anything. Active reconnaissance is where the observer 
becomes participant, where watching becomes touching, and where caution becomes paramount.

The Patrician's directive remained absolute: learn without disrupting. In IT security, a crashed service during 
testing is an awkward conversation. In operational technology, a crashed service is a turbine offline, lights 
flickering across the city, and a conversation with the Patrician that ends careers and possibly more.

This is the account of careful, methodical active probing of the UU P&L simulator. Each action was measured. Each 
response was analysed. Each step forward required certainty that the previous step caused no harm.

## The first touch

The passive map showed `port 10502` as the busiest device, deep in constant conversation with its supervisor. To probe 
it was to tap a shoulder mid-discussion. The approach required protocol courtesy—speak the language, observe the 
customs, ask only polite questions.

The first test was the simplest: does the device speak when spoken to? The script 
[`raw-tcp-probing.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/recon/raw-tcp-probing.py) 
performed the gentlest possible Modbus query. Read a single holding register. Address zero. Function code 3. 
The universal question in Modbus: "What is your status?"

```bash
$ python scripts/recon/raw-tcp-probing.py
[*] Testing Modbus TCP connectivity at 127.0.0.1:10502
[*] Connected successfully
[*] Reading holding register 0...
[✓] Response received: 1500
[*] Device is responsive to Modbus TCP queries

Connection successful. Port 10502 is a working Modbus TCP endpoint.
```

The response came cleanly. Register zero held the value `1500`. No alarms triggered. No services crashed. The device 
had answered a polite question politely. This was the permission to continue.

The value itself, `1500`, suggested a setpoint. Perhaps RPM for a turbine. But interpretation required more context. 
First, establish what the device claims to be.

## Device identity

Modbus TCP specification includes Function Code 43, also known as MEI Type 14: Read Device Identification. This is 
the protocol's way of asking "Who are you?" It returns vendor name, product code, model information, and firmware 
version. Not all devices implement it. Those that do provide a wealth of reconnaissance data in a single, legitimate, 
protocol-compliant query.

The script [`modbus_identity_probe.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/recon/modbus_identity_probe.py) 
sends this query to discovered devices:

```bash
$ python scripts/recon/modbus_identity_probe.py
[*] Probing device identity on discovered Modbus endpoints...

[*] Probing 127.0.0.1:10502
  VendorName: Wonderware
  ProductCode: SCADA-2024
  MajorMinorRevision: 1.0
  VendorUrl: www.wonderware.com
  ProductName: Wonderware System Platform
  ModelName: InTouch SCADA

[*] Probing 127.0.0.1:10503
  VendorName: Wonderware
  ProductCode: SCADA-2024
  MajorMinorRevision: 1.0
  (Additional devices show identical information - simulator limitation)
```

The response revealed a curious uniformity. Every device identified itself as "Wonderware SCADA-2024". This was clearly 
a simulator artefact, not operational reality. In a real deployment, each device would have distinct identity, 
Siemens S7-315 here, Allen-Bradley ControlLogix there, Schneider Modicon elsewhere.

But the uniformity itself was information. It confirmed we were working with a simulator. It demonstrated that the 
devices implemented the Read Device Identification function. And it showed that someone had configured these 
identities, even if they hadn't differentiated them.

The script saved detailed results to `reports/device_identity_probe_*.json` for later analysis.

## Telemetry reading

With basic connectivity and identity confirmed, the next step was reading actual operational data. The script 
[`turbine_recon.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/recon/turbine_recon.py) 
performs a reconnaissance read of turbine telemetry registers, the data a SCADA operator would see:

```bash
$ python scripts/recon/turbine_recon.py
[*] Turbine Control System Reconnaissance
[*] Target: 127.0.0.1:10502 (Turbine PLC)
[*] Performing safe telemetry read (no writes, no modification)

=== TURBINE STATUS ===
Speed Setpoint (HR 0):        1500 RPM
Power Output Setpoint (HR 1): 0 MW

Current Speed (IR 0):         1503 RPM
Current Power (IR 1):         15 MW
Bearing Temperature (IR 2):   45°C
Oil Pressure (IR 3):          8 bar
Vibration Level (IR 4):       2 mm/s
Generator Temperature (IR 5): 62°C
Gearbox Temperature (IR 6):   58°C
Ambient Temperature (IR 7):   22°C

Control Mode (Coil 0):        AUTO
Emergency Stop (Coil 1):      INACTIVE
Maintenance Mode (Coil 2):    INACTIVE

Overspeed Alarm (DI 0):       OK
Low Oil Pressure (DI 1):      OK
High Bearing Temp (DI 2):     OK
High Vibration (DI 3):        OK
Generator Fault (DI 4):       OK

[*] Turbine appears to be operating normally
[*] All alarm states are OK (safe condition)
[*] Telemetry reconnaissance complete - no alarms triggered
```

This was the full picture. A wind turbine (the speed and power output suggested wind, not steam or hydro) operating 
at rated speed with normal temperatures and pressures. All discrete inputs showed "OK" status,no alarms, no faults.

The data structure revealed the PLC's memory map:
- Holding Registers 0-1: Setpoints (operator-configurable targets)
- Input Registers 0-7: Live sensor readings (read-only telemetry)
- Coils 0-2: Control modes (binary on/off switches)
- Discrete Inputs 0-4: Alarm states (binary status indicators)

This map would guide deeper [discovery](discovery.md). But for reconnaissance, it provided operational context: 
we knew what this device did, what it monitored, and what control it offered.

## Protocol diversity

Industrial networks rarely speak only Modbus. The [passive capture](passive.md) showed traffic on various ports. Port 
`10510` showed minimal traffic,only 4 packets in the entire capture. This suggested a different protocol, perhaps 
event-driven rather than polled.

Port `63342` showed a different pattern entirely,lower frequency, larger packet sizes. The script 
[`connect-remote-substation.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/recon/connect-remote-substation.py) 
tested for OPC UA, a more modern industrial protocol common in newer SCADA systems:

```bash
$ python scripts/recon/connect-remote-substation.py
[*] OPC UA Substation Reconnaissance
[*] Target: opc.tcp://127.0.0.1:63342

[*] Connecting to OPC UA server...
[✓] Connected successfully

[*] Reading server information...
  Server Name: Substation Controller
  Server State: Running
  Build Info: UU P&L Substation Control v1.0

[*] Browsing available nodes...

  Root Objects:
    - BreakerStatus
    - VoltageReadings
    - CurrentReadings
    - AlarmConditions
    - SubstationConfig

[*] Reading sample values...
  BreakerStatus/Main: CLOSED
  VoltageReadings/PhaseA: 11.2 kV
  VoltageReadings/PhaseB: 11.1 kV
  VoltageReadings/PhaseC: 11.3 kV

[*] OPC UA reconnaissance complete
[*] Substation controller is accessible and functional
```

This was a different control domain entirely. Not turbines but substations,the electrical distribution equipment 
between generation and consumption. The OPC UA server exposed a structured object hierarchy with breaker states and 
voltage readings. Unlike Modbus's flat register addressing, OPC UA provides named objects and organised hierarchies.

The diversity of protocols confirmed this was a comprehensive simulation: multiple control domains, multiple protocol 
implementations, a realistic heterogeneous environment.

## Network layer probing

The final reconnaissance test operated below the application layer. Sometimes the most revealing information comes 
not from what services say, but from how the network itself responds. The script 
[`query-substation-controller.py`](https://github.com/tymyrddin/power-and-light-sim/blob/main/scripts/recon/query-substation-controller.py) 
uses Scapy to send raw TCP SYN packets and analyse responses:

```bash
$ sudo .venv/bin/python scripts/recon/query-substation-controller.py
[*] Network-Layer Substation Reconnaissance
[*] Target: 127.0.0.1
[*] Using raw socket probing (requires root)

[*] Scanning common ICS ports...
  Port 102 (S7comm):     CLOSED (RST received)
  Port 502 (Modbus):     CLOSED (RST received)
  Port 10502 (Custom):   OPEN (SYN-ACK received)
  Port 10503 (Custom):   OPEN (SYN-ACK received)
  Port 10510 (Custom):   OPEN (SYN-ACK received)
  Port 63342 (OPC UA):   OPEN (SYN-ACK received)

[*] Analysing TCP/IP stack behaviour...
  TTL: 64 (likely Linux/Unix host)
  Window Size: 65535 (default)
  TCP Options: MSS, SACK permitted, timestamps, window scale

[*] OS Fingerprint suggests: Linux 3.x/4.x

[*] Network reconnaissance complete
[*] Standard ICS ports (102, 502) are not in use
[*] Custom port range 10500-10520 hosts industrial services
```

This revealed the deliberate port offset—standard ICS protocols moved from their default ports to a custom range. This 
is common in simulator environments to avoid conflicts with other services and to allow multiple simulator instances 
on one machine.

The TCP/IP stack fingerprint suggested a Linux host, consistent with running the simulator on a development machine. 
In a real deployment, these fingerprints would show embedded operating systems, proprietary TCP stacks, and 
device-specific behaviours.

## The gaps and the limits

Active reconnaissance also revealed what wasn't present. Two recon scripts failed to find their targets:

EtherNet/IP Protocol ([`enumerate-device.py`](https://github.com/ninabarzh/power-and-light-sim/blob/main/scripts/recon/enumerate-device.py)):

```bash
$ python scripts/recon/enumerate-device.py
[!] ERROR: Connection refused to port 44818
[*] EtherNet/IP service not available
[*] This protocol is not implemented in the simulator
```

EtherNet/IP is common in Allen-Bradley and Rockwell Automation systems. Its absence was noted but not concerning for 
a simulator focused on Modbus and OPC UA implementations.

Siemens S7 Protocol ([`query-plc.py`](https://github.com/ninabarzh/power-and-light-sim/blob/main/scripts/recon/query-plc.py)):

```bash
$ python scripts/recon/query-plc.py
[!] ERROR: Permission denied on ports 102/103
[*] S7comm requires privileged ports (<1024)
[*] Run with sudo or configure capabilities for non-root access
[*] Alternatively, configure simulator to use high ports
```

The S7 protocol's requirement for privileged ports (102/103) created an operational constraint. This was documented as 
a limitation, not a failure. The simulator could be run with capabilities or the S7 server could be reconfigured to 
use high ports if S7 testing became a priority.

These failures were as informative as successes. They defined the boundaries of the test environment and identified 
where future development might focus.

## The reconnaissance map

Active reconnaissance transformed the [passive traffic analysis](passive.md) into operational knowledge:

Port 10502-10506: Modbus TCP endpoints, responding to standard queries, implementing device identification, 
hosting turbine telemetry with realistic sensor values and control registers.

Port 10510: Minimal traffic device, responsive but quiet. Likely event-driven rather than polled. Function unclear 
from reconnaissance alone,requires deeper [discovery](discovery.md).

Port 10520: Supervisory endpoint, bridges multiple protocols, aggregates data from field devices. Acts as a gateway 
between the control layer and monitoring layer.

Port 63342: OPC UA server, hosting substation control objects, providing structured hierarchical data access, 
implementing modern industrial protocol standards.

Ports 102, 502, 44818: Not in use. Standard ICS protocols either not implemented or running on alternate ports.

This map provided the foundation for the next phase. Active reconnaissance answered "what is there?" Now 
[discovery](discovery.md) would answer "what can we learn from what is there?"

## The lesson of careful touch

Every probe was gentle. Every query was legitimate. Every response was analysed before proceeding. The turbines kept 
spinning. The voltage stayed stable. The simulator continued its faithful replication of operational systems.

Active reconnaissance in OT environments is not about speed or aggression. It's about precision and caution. It's 
about asking questions the system is designed to answer, in the language it expects, at a pace it can handle.

The Patrician's directive was satisfied. Knowledge was gained. No lights flickered. No alarms sounded. The 
reconnaissance phase was complete.

Now came the deeper work: [systematic discovery](discovery.md) of memory maps, register ranges, and the detailed structure 
hiding within those registers. But that required a different approach entirely—one based not on probing, but on 
methodical enumeration.

And that, as they say, is another day's work.
