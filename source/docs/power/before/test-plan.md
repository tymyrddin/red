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

Testing targets the devices and network zones modelled in the lab, grouped by zone.

*   Internet (10.10.0.0/24): `unseen-gate` (entry point), `wizzards-retreat`.
*   Enterprise (10.10.1.0/24): `bursar-desk`, `hex-legacy-1`.
*   Operational (10.10.2.0/24): `uupl-historian`, `distribution-scada`, `uupl-eng-ws`, `uupl-modbus-gw`.
*   Control (10.10.3.0/24): `uupl-hmi`, `hex-turbine-plc` and its `hex-turbine-opcua` sidecar, the protective relays `uupl-relay-a` and `uupl-relay-b`, `uupl-meter`, the Modbus actuators (`uupl-fuel-valve`, `uupl-cooling-pump`, `uupl-breaker-a`, `uupl-breaker-b`), and `uupl-mqtt`.
*   DMZ, the Guild Quarter (10.10.5.0/24): `contractors-gate` (SSH bastion), `guild-exchange` (umatiGateway), `sorting-office` (Neuron gateway), `clacks-relay` (MQTT), `guild-register` (OPC-UA), `substation-rtu` (IEC-104), `guild-clock` (NTP), `city-directory` (DNS), `scribes-post` (syslog), `dispatch-box` (SFTP).

### 2.2 Explicitly out-of-scope systems

*   Any physical UU P&L asset not represented in the lab. The simulation is the sole territory for testing.
*   Real-world Ankh-Morpork infrastructure. Only what the lab models is in scope.
*   External vendor infrastructure. Only the modelled remote-access path, the WireGuard config left lying around on `wizzards-retreat`, is in scope as an attack vector.

### 2.3 Grey areas and clarifications
*   Protective relays (`uupl-relay-a`, `uupl-relay-b`): in scope for observation and for the documented threshold and trip behaviour. They are the closest thing the lab has to a safety function, so write tests against their thresholds count as high-consequence and stay confined to isolated runs.
*   The legacy workstation (`hex-legacy-1`): in scope as a pivot and for enumeration, though its vintage may behave unpredictably. This is a feature, not a bug.

## 3.0 Test architecture & dependency mapping

The test environment is the simulator itself. Dependencies are not operational, but causal, as defined by the simulator's layered architecture.

### 3.1 Key attack surfaces & dependencies
*   Primary Attack Path: `unseen-gate` → `contractors-gate` (SSH bastion, CVE-2024-6387) → enterprise → `uupl-eng-ws` (operational) → control-zone targets. This tests the Purdue Model bypass.
*   Alternative entry: `wizzards-retreat`'s WireGuard config bridges the internet zone straight into enterprise, skipping the bastion.
*   Direct Control Path: an attacker on the control network sends Modbus to `hex-turbine-plc` on port 502, or to a relay or actuator. Tests network segregation failure.
*   Protection Bypass: writing a new threshold to `uupl-relay-a` so the breaker trips, or fails to, on apparently legitimate grounds. Tests the protection design.
*   Protocol-Specific Vectors: unauthenticated Modbus, DNP3, and IEC-104 against the field devices; anonymous OPC-UA method calls via `guild-register` and the turbine sidecar; IEC-104 datapoint falsification at `substation-rtu`.

### 3.2 Simulator-specific considerations
*   Physics: attacks that trip `hex-turbine-plc` or a feeder breaker produce a cascading effect in the lab's process model. This is a success condition, not a failure.
*   The clock as a target: `guild-clock` hands out the time the rest of the estate trusts. Moving it disrupts certificate validation and log correlation, which is itself a tested effect.

## 4.0 Test windows & operational cadence

Testing is decoupled from real-world operational cycles. "Test windows" refer to scheduled simulator runtime dedicated to specific attack scenarios.

*   Phase 1 - Reconnaissance: Passive mapping of the lab network and protocol discovery using `nmap` and `Wireshark` against the service ports (502, 2404, 20000, 4840, 1883, 161, 1881, and the usual SSH, DNS, and NTP).
*   Phase 2 - Vulnerability Validation: Active, non-destructive probing (reading registers from the Modbus devices, browsing the anonymous OPC-UA endpoints).
*   Phase 3 - Controlled Exploitation: Execution of specific attack chains in isolated lab instances.
*   Phase 4 - Demonstration & Documentation: Re-run of successful attack paths for evidence capture and metrics generation.

## 5.0 Success criteria & abort conditions

### 5.1 Success criteria
The test is successful when:
1.  Path Proven: A complete attack path from a low-privilege entry point (e.g., the `finance_workstation`) to a high-impact physical effect (e.g., turbine trip) is demonstrated within the simulator.
2.  Causality Documented: Every step of the path, from packet to protocol semantics to device logic to physics engine change, is logged by the simulator's security layer.
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
*   Protocol Interaction: `mbtget` or `pymodbus` for Modbus, `pydnp3` for DNP3, a `c104` client for IEC-104, `opcua-asyncio` for OPC UA. All commands are logged.
*   Attack Simulation: Custom Python using the above libraries, following the attack paths defined in Section 3.1.
*   Evidence: the lab's own log output, screen captures of HMI changes (`uupl-hmi`), and plots of process outputs (turbine RPM, breaker state).

Document Approval: This plan acknowledges that the only safe way to break a city's power grid is to first build a 
perfect, breakable model of it. The simulator is that model. This plan is our agreement on how to break it usefully.

*Ponder Stibbons*

*Lecturer in Applied Inconveniences*

*Unseen University, Ankh-Morpork*
