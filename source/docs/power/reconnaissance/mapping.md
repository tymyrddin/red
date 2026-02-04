# Mapping

*Extract from the Field Notes of Ponder Stibbons*

[Passive reconnaissance](passive.md) revealed the conversations. [Active reconnaissance](active.md) confirmed the 
participants. [Discovery](discovery.md) mapped their internals. Now came the work of assembling these fragments into a 
comprehensive picture: the complete architecture of the UU P&L control infrastructure.

This was mapping, not of the physical turbine hall or cable trays, but of the logical architecture. The devices, 
their relationships, their dependencies, and the invisible structure that held it all together.

## The asset inventory

Every reconnaissance begins with answering "what exists?" but mapping asks "how does it all fit together?" The first 
step was documenting the discovered assets in structured form.

From reconnaissance and discovery, the inventory emerged:

### Control Layer Devices

Turbine PLC 1 (127.0.0.1:10502)
- Type: Modbus TCP PLC
- Function: Primary turbine speed and power control
- Memory Map: 2 holding registers (setpoints), 10 input registers (telemetry), 3 coils (control modes), 8 discrete inputs (alarms)
- Criticality: Critical - controls 33% of facility power generation
- Device Identity: Wonderware SCADA-2024 (simulator artefact)

Turbine PLC 2 (127.0.0.1:10503)
- Type: Modbus TCP PLC
- Function: Secondary turbine, identical configuration to PLC 1
- Memory Map: Identical to Turbine PLC 1
- Criticality: Critical
- Notes: Shares same device identity with all devices (pymodbus 3.11.4 limitation)

Turbine PLC 3 (127.0.0.1:10504)
- Type: Modbus TCP PLC
- Function: Tertiary turbine
- Criticality: Critical
- Notes: Third redundant turbine controller

Reactor PLC (127.0.0.1:10505)
- Type: Modbus TCP PLC
- Function: Reactor temperature and cooling control
- Memory Map: Similar structure, different sensor types (temperatures, pressures, cooling flow)
- Criticality: Critical - safety implications if cooling fails

Cooling System PLC (127.0.0.1:10506)
- Type: Modbus TCP PLC
- Function: Auxiliary cooling and environmental controls
- Criticality: High - supports reactor and turbine cooling

### Supervisory Layer

SCADA Server (127.0.0.1:10520)
- Type: Modbus TCP Gateway/Aggregator
- Function: Centralized monitoring and control, polls all field devices
- Polling Interval: ~5 seconds per device (observed in passive capture)
- Criticality: High - loss of SCADA means loss of centralised visibility
- Notes: Accepts external connections (reconnaissance entry point)

Substation Controller (127.0.0.1:63342)
- Type: OPC UA Server
- Function: Electrical distribution monitoring and breaker control
- Exposed Objects: BreakerStatus, VoltageReadings, CurrentReadings, AlarmConditions
- Criticality: Critical - manages power distribution to city
- Protocol: OPC UA (modern hierarchical protocol vs. flat Modbus addressing)

### Auxiliary Systems

Remote Terminal Unit (127.0.0.1:10510)
- Type: Unknown (minimal traffic, event-driven)
- Function: Unclear from reconnaissance (only 4 packets captured passively)
- Criticality: Unknown - requires further investigation
- Notes: Responds to connections but purpose not yet determined

This inventory represented not just "things on the network" but operational context. Each device had a purpose. 
Each had criticality. Each had dependencies.

## The network architecture

The simulator's network architecture was deliberately simple, all services on localhost, using port offsets to avoid 
conflicts. This was unrealistic compared to operational OT networks (which span multiple physical networks, VLANs, 
and security zones), but it faithfully represented the logical relationships:

```
┌─────────────────────────────────────────────────────────────┐
│                     Supervisory Layer                       │
│  ┌───────────────────┐           ┌───────────────────┐      │
│  │  SCADA Server     │           │ Substation Ctrl   │      │
│  │  (Port 10520)     │◄─────────►│  (Port 63342)     │      │
│  │  Modbus Gateway   │           │  OPC UA Server    │      │
│  └────────┬──────────┘           └───────────────────┘      │
│           │                                                 │
│           │ Polls every 5s                                  │
│           │                                                 │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                       Control Layer                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Turbine  │  │ Turbine  │  │ Turbine  │  │ Reactor  │     │
│  │  PLC 1   │  │  PLC 2   │  │  PLC 3   │  │   PLC    │     │
│  │  (10502) │  │  (10503) │  │  (10504) │  │  (10505) │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
│       │             │             │             │           │
│       ▼             ▼             ▼             ▼           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ Physical │  │ Physical │  │ Physical │  │ Reactor  │     │
│  │ Turbine  │  │ Turbine  │  │ Turbine  │  │ Coolant  │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└─────────────────────────────────────────────────────────────┘
```

The SCADA server sat at the supervisory layer, polling field devices. The substation controller operated in parallel, 
monitoring electrical distribution while SCADA monitored generation. The control layer PLCs interfaced directly with 
physical processes through simulated physics models.

## Configuration architecture

The simulator's configuration files revealed the architectural decisions that shaped the environment. The configuration 
lives in [`config/`](https://github.com/ninabarzh/power-and-light-sim/tree/main/config):

[`devices.yml`](https://github.com/ninabarzh/power-and-light-sim/blob/main/config/devices.yml) - Defined each device's 
type, sensors, actuators, and initial state:

```yaml
turbine_plc_1:
  type: turbine_plc
  sensors:
    - speed
    - power_output
    - bearing_temperature
    - oil_pressure
    - vibration
    - generator_temperature
    - gearbox_temperature
    - ambient_temperature
  actuators:
    - speed_setpoint
    - power_setpoint
```

Each device's configuration explicitly listed its I/O points. This was why [discovery](discovery.md) found exactly 8 
active input registers, they were defined in configuration, not arbitrary memory ranges.

[`protocols.yml`](https://github.com/ninabarzh/power-and-light-sim/blob/main/config/protocols.yml) - Mapped devices 
to network services:

```yaml
modbus_tcp:
  turbine_plc_1:
    host: "127.0.0.1"
    port: 10502
  turbine_plc_2:
    host: "127.0.0.1"
    port: 10503
  scada_server:
    host: "127.0.0.1"
    port: 10520
```

This explained the port assignments discovered during [passive reconnaissance](passive.md). The port numbers weren't 
arbitrary, they were deliberately configured to avoid conflicts with standard ICS ports (502, 102, etc.) while 
maintaining logical grouping (105xx for field devices, 635xx for supervisory systems).

[`device_identity.yml`](https://github.com/ninabarzh/power-and-light-sim/blob/main/config/device_identity.yml) defined 
Modbus device identities for FC 43 responses:

```yaml
device_identities:
  turbine_plc:
    vendor: "Allen-Bradley"
    product_code: "1756-L73"
    model: "ControlLogix 5570"
    revision: "20.011"

  scada_server:
    vendor: "Wonderware"
    product_code: "SCADA-2024"
    model: "System Platform"
    revision: "1.0"
```

The configuration included realistic vendor identities for multiple device types. However, the pymodbus 3.11.4 bug 
caused all devices to report the same identity (the last one initialised). This was a simulator limitation, not an 
architectural choice, but it didn't affect functionality, only fingerprinting accuracy.

## Data flow patterns

Mapping data flows revealed the system's operational rhythm. From passive capture analysis and SCADA polling patterns:

Control Loop (Continuous, 5-second cycle):
```
SCADA (10520) → READ Input Registers → Turbine PLC (10502)
               ← Telemetry Data ←

Operator → WRITE Holding Register → SCADA (10520) → Turbine PLC (10502)
                                                   → Setpoint Updated
```

This was the fundamental control loop: SCADA polls, gets telemetry, displays to operator. Operator adjusts setpoint, 
SCADA writes to PLC, turbine responds. Continuous, predictable, observable in traffic captures.

Physics Simulation (Internal, ~100ms cycle):
```
PLC Holding Register (Setpoint)
    ↓
Control Algorithm (PID)
    ↓
Physical Model (turbine dynamics, thermal models, mechanical constraints)
    ↓
PLC Input Registers (Actual values)
    ↓
SCADA Telemetry
```

The physics simulation ran internally within each PLC model. The ±3 RPM oscillation observed during 
[discovery](discovery.md) came from this control loop, realistic PID behaviour hunting around the setpoint with 
real-world disturbances.

Alarm Propagation (Event-driven):
```
Physical Condition (e.g., speed > 1600 RPM)
    ↓
PLC Logic evaluates discrete inputs
    ↓
Discrete Input 0 (Overspeed Alarm) = TRUE
    ↓
SCADA polls discrete inputs
    ↓
Operator alarm display
```

Alarms flowed from physical conditions through PLC logic to SCADA display. The discrete inputs discovered during 
enumeration weren't arbitrary, they represented the alarm infrastructure.

## Critical dependencies

Mapping dependencies revealed what depended on what, the invisible threads that would cascade failures through the system:

Turbine Operation Dependencies:
- Turbine PLC must be powered and running
- Network connectivity between PLC and SCADA required for remote monitoring (but not for autonomous operation)
- SCADA server required for operator visibility and remote setpoint changes
- Physical model must execute correctly for realistic behaviour

SCADA Visibility Dependencies:
- Network connectivity to all field devices
- Modbus TCP service operational on each PLC
- Correct port configurations (10502-10506, 10520)
- No network segmentation blocking control traffic

Attack Surface Dependencies:
- No authentication on Modbus writes (discovered during [test_write_permissions.py](https://github.com/ninabarzh/power-and-light-sim/blob/main/scripts/discovery/test_write_permissions.py))
- Direct network access to PLCs (no firewall between SCADA and field devices)
- All unit IDs respond (no unit ID validation, discovered during [scan_unit_ids.py](https://github.com/ninabarzh/power-and-light-sim/blob/main/scripts/discovery/scan_unit_ids.py))

The lack of authentication was architectural. Modbus TCP has no authentication mechanism. This wasn't a configuration error, it was the protocol's design. The simulator faithfully replicated this vulnerability.

## Trust boundaries (or lack thereof)

In operational OT networks, trust boundaries separate control zones, safety systems from control systems, corporate 
networks from OT networks. The simulator's architecture deliberately omitted these boundaries:

No Authentication Boundary:
- Any network client can connect to any Modbus port
- No credentials required for read or write operations
- No session management or access control

No Safety System Isolation:
- All PLCs on same logical network (same host, different ports)
- Safety-critical reactor PLC (10505) accessible via same methods as operational turbine PLCs
- No dedicated safety network or isolation

No Segmentation:
- All devices share localhost network space
- SCADA server has direct access to all field devices
- No VLANs, no firewalls, no network isolation

This flat architecture was realistic for the simulator's purpose. Real OT networks often have similarly flat 
topologies, especially legacy installations or poorly secured facilities. The UU P&L simulator modelled a vulnerable 
but operational architecture.

## The simulator's honest architecture

Mapping revealed that the simulator made deliberate architectural choices:

- Simplicity over realism - Localhost deployment with port offsets rather than distributed network architecture. This enabled single-machine testing while preserving logical relationships.
- Transparency over security - No authentication, no access control, no segmentation. This enabled security research and attack demonstration without requiring exploit development for authentication bypass.
- Realistic protocols - Actual Modbus TCP, actual OPC UA, actual protocol behaviours. Not "toy" implementations but real industrial protocol stacks (pymodbus, asyncua).
- Physics simulation - Realistic control loop behaviour, thermal dynamics, mechanical constraints. Values weren't random, they followed physical laws.
- Deliberate limitations - The pymodbus device identity bug, the unit ID validation issue, the compact memory maps. These were known limitations, documented in [Simulator gaps](https://github.com/ninabarzh/power-and-light-sim/blob/main/SIMULATOR_GAPS.md).

The simulator's architecture was honest. It didn't hide its nature. It didn't pretend to be production infrastructure. 
It provided a realistic test environment for security research, pentesting techniques, and attack demonstration.

## The complete picture

After passive observation, active probing, systematic discovery, and architectural mapping, the complete picture emerged:

- 7 control devices across 3 turbines, 1 reactor, 1 cooling system, plus SCADA and substation controllers
- 2 protocols - Modbus TCP and OPC UA
- 23 I/O points per Modbus device (compact but complete)
- 5-second polling from SCADA to field devices
- No authentication on any service
- Realistic physics simulation running internally
- Documented limitations that don't affect core functionality

This was the UU P&L Power & Light control infrastructure. Not as complex as actual city power systems, but faithful to 
their architecture. Vulnerable by design, transparent for research, and realistic enough for meaningful security 
testing.

The map was complete. The architecture was documented. The dependencies were known.

Now came the question: what happens when you modify a system this transparent? What attacks become possible with 
this complete map?

That's where [exploitation](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/exploitation) enters the story. The turbine overspeed attacks, the emergency stop demonstrations, 
the gradual manipulation that stays below alarm thresholds.

But those are not reconnaissance or mapping. Those are demonstrations of capability, showing what an adversary could 
accomplish with the knowledge we've gathered.

And that, as the Patrician would say, is why we map before we act. Knowledge before action. Understanding before 
intervention.

The reconnaissance was complete. The mapping was done. The simulator had revealed not just its components, but its 
structure, its rhythms, and its vulnerabilities.

From here, the work transitions from "what is it?" to "what can be done with it?" A different kind of work entirely. 
Still careful. Still documented. But no longer passive observation.

Active demonstration.

---

*End of Field Notes: Reconnaissance and Mapping Phase*
*Status: Complete*
*Next Phase: Exploitation and Impact Analysis*
*Authorisation: Required before proceeding*
