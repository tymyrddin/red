# Industrial control system security assessment

Test Plan Document HEM/OTSEC/001
*Authorised by: Ponder Stibbons, Lecturer in Applied Inconveniences*

## 1.0 Executive summary & objectives

This document outlines the security assessment methodology for the Unseen University Power & Light Co. (UU P&L) 
operational technology (OT) environment. The primary objective is to identify and demonstrate security vulnerabilities 
within a fully simulated, causally correct twin of the critical infrastructure, thereby quantifying risk without 
exposing the live city systems to operational disruption.

The assessment will leverage the UU P&L ICS Simulator, a layered model of the power generation and distribution 
network. Success is defined not by the compromise of live systems, but by the demonstrable proof that specific attack 
paths exist within the simulated architecture, providing unambiguous evidence for remedial action.

## 2.0 Scope definition

The scope is bounded by the simulated environment. All testing occurs within the virtualised network and physics 
engines, with no interaction permitted with live UU P&L systems.

### 2.1 In-Scope systems (simulator assets)

Testing will target all configured devices and network zones within the simulator, as defined in [/config/](https://github.com/ninabarzh/power-and-light-sim/tree/main/config).

*   By Device Name ([devices.yml](https://github.com/ninabarzh/power-and-light-sim/blob/main/config/devices.yml)):
    *   Hex Steam Turbine System: `hex_turbine_plc`, `hex_turbine_safety_plc`
    *   Alchemical Reactor System: `reactor_plc`, `reactor_safety_plc`
    *   Library Environmental System: `library_hvac_plc`, `library_lspace_monitor`
    *   Distribution SCADA: `substation_rtu_1`, `substation_rtu_2`, `substation_rtu_3`
    *   Operations & Supervision: `scada_server_primary`, `scada_server_backup`, `hmi_operator_1`, `hmi_operator_2`, `hmi_operator_3`, `hmi_operator_4`, `engineering_workstation`
    *   Enterprise Data Systems: `historian_primary`, `legacy_data_collector`, `finance_workstation`

*   By Network Zone ([network.yml](https://github.com/ninabarzh/power-and-light-sim/blob/main/config/network.yml) - Purdue model alignment):
    *   Control Zone (Level 0-2): The `turbine_network` (10.10.1.0/24), `reactor_network` (10.10.2.0/24), `library_network` (10.10.3.0/24), and `distribution_network` (10.10.10.0/24).
    *   Operations Zone (Level 3): The `scada_network` (10.20.1.0/24), `hmi_network` (10.20.2.0/24), and `engineering_network` (10.20.3.0/24).
    *   DMZ & Enterprise Zone (Level 3.5-4): The `dmz_network` (10.30.1.0/24) and `historian_network` (10.40.1.0/24). These are primarily targets for pivot and exfiltration testing.

### 2.2 Explicitly out-of-scope systems

*   Any physical UU P&L asset not represented in the simulator. The simulation is the sole territory for testing.
*   The real-world Library climate control system. The simulated `library_hvac_plc` is in scope; the actual Librarian's domain is emphatically not.
*   External vendor infrastructure. Only the simulated VPN pathway on the `finance_workstation` is in scope as an attack vector.

### 2.3 Grey areas and clarifications
*   Safety PLCs: The simulated safety systems (`hex_turbine_safety_plc`, `reactor_safety_plc`) are in scope for observation and passive analysis (e.g., protocol interrogation). Active attempts to disable or corrupt them are permitted only in designated, isolated test scenarios with the physics engines set to "zero-consequence" mode.
*   The Legacy Data Collector (`legacy_data_collector`): In scope for protocol fuzzing (serial) and as a pivot point, but its vintage Windows 98 simulation may behave unpredictably. This is a feature, not a bug.

## 3.0 Test architecture & dependency mapping

The test environment is the simulator itself. Dependencies are not operational, but causal, as defined by the simulator's layered architecture.

### 3.1 Key attack surfaces & dependencies
*   Primary Attack Path: `finance_workstation` (Enterprise Zone) → `historian_primary` (DMZ/Enterprise) → `scada_server_primary` (Operations Zone) → Target PLC (Control Zone). This tests the Purdue Model bypass.
*   Direct Control Path: Attacker in `engineering_network` → Direct Modbus/TCP to `hex_turbine_plc` on port 10502. Tests network segregation failure.
*   Safety System Bypass: Compromise of `reactor_plc` with goal of triggering a shutdown before the independent `reactor_safety_plc` can react. Tests safety system design.
*   Protocol-Specific Vectors: As catalogued in `protocols.yml`, including unauthenticated S7 stop commands to `reactor_plc` and Modbus function code manipulation against `library_hvac_plc`.

### 3.2 Simulator-specific considerations
*   Physics Engine Integration: Attacks causing a simulated trip of the `hex_turbine_plc` will result in a cascading shutdown in the `turbine_physics` model. This is a success condition, not a failure.
*   Time Orchestration: The deterministic `time/` component allows any successful attack to be rewound and replayed for analysis and demonstration.

## 4.0 Test windows & operational cadence

Testing is decoupled from real-world operational cycles. "Test windows" refer to scheduled simulator runtime dedicated to specific attack scenarios.

*   Phase 1 - Reconnaissance: Passive mapping of simulated network (`network.yml` topology) and protocol discovery using `nmap` and `Wireshark` against simulator ports (10502, 102, 20000, 4840, etc.).
*   Phase 2 - Vulnerability Validation: Active, non-destructive probing based on `protocols.yml` vulnerability list (e.g., reading registers from all Modbus devices).
*   Phase 3 - Controlled Exploitation: Execution of specific attack scenarios (e.g., "turbine_fault" or "cyber_attack" from `simulation.yml`) in isolated simulator instances.
*   Phase 4 - Demonstration & Documentation: Re-run of successful attack paths for evidence capture and metrics generation.

## 5.0 Success criteria & abort conditions

### 5.1 Success criteria
The test is successful when:
1.  Path Proven: A complete attack path from a low-privilege entry point (e.g., the `finance_workstation`) to a high-impact physical effect (e.g., turbine trip) is demonstrated within the simulator.
2.  Causality Documented: Every step of the path—from packet to protocol semantics to device logic to physics engine change—is logged by the simulator's security layer.
3.  Evidence Compiled: A reproducible script, sequence of commands, or packet capture exists for each proven vulnerability.
4.  The Patrician is Convinced: The findings can be presented as a narrative of cause and effect, not a list of technical anomalies.

### 5.2 Abort conditions
Testing within the simulator shall be paused or halted if:
1.  Simulator Integrity Fails: The simulation state becomes unrecoverable or non-deterministic.
2.  Causal Chain Obscured: An attack succeeds but the layered logging fails to capture the sequence, making the result anecdotal rather than evidential.
3.  Resource Exhaustion: The simulation consumes more computational resources than the HEM building's cooling system can handle.

## 6.0 Communication & reporting protocol

All communication is internal to the HEM project team.
*   Status Updates: Logged directly to the `security/` layer of the simulator and reviewed daily.
*   Evidence Collection: All proof-of-concept code, packet captures (`.pcap`), and simulator logs will be stored in the project repository under `/tests/scenario/evidence/`.
*   Final Deliverable: A report structured not as a pentest, but as a "Forensic Analysis of a Simulated Incident," detailing the attack narrative, the simulator's recorded evidence at each layer, and specific, actionable recommendations for the *real* UU P&L architecture.

## 7.0 Tools & methodologies

Tools will be selected for their ability to interact with the simulator's exposed services and to generate clear evidence.

*   Reconnaissance: `nmap` against simulator IP ranges, `Wireshark` with OT protocol dissectors.
*   Protocol Interaction: `mbtget` for Modbus, `python-snap7` for S7, `pydnp3` for DNP3, `opcua-asyncio` client for OPC UA. All commands must be logged.
*   Attack Simulation: Custom Python scripts using the above libraries, designed to execute the attack paths defined in Section 3.1.
*   Evidence: Simulator's own log output, screen captures of HMI changes (`hmi_operator_1`), and plots of physics engine outputs (turbine RPM, reactor temperature).

Document Approval: This plan acknowledges that the only safe way to break a city's power grid is to first build a 
perfect, breakable model of it. The simulator is that model. This plan is our agreement on how to break it usefully.

*Ponder Stibbons*

*Lecturer in Applied Inconveniences*

*Unseen University, Ankh-Morpork*
