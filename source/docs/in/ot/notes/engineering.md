# Engineering workstations as crown jewels

The engineering workstation is the most valuable target in an OT environment. It holds the ladder logic and function block diagrams that define process behaviour, the project files that document every I/O address and its meaning, the credentials for every PLC and device the engineer manages, and the software tools that can compile and deploy new logic without any approval workflow other than pressing download.

Compromising a PLC directly modifies one device. Compromising the engineering workstation provides the tools, knowledge, and credentials to modify every device that engineer manages, and to do so in a way that looks like normal maintenance.

## What an engineering workstation contains

Siemens TIA Portal (Totally Integrated Automation Portal) is the engineering environment for S7-1200, S7-1500, and S7-300/400 PLCs. A TIA Portal project file contains the complete logic for all devices in the project, including hardware configuration, tag databases, program blocks, safety logic, and the HMI screen definitions. The project file is the blueprint for the entire automated process.

Rockwell Automation Studio 5000 (formerly RSLogix 5000) serves the same function for Allen-Bradley PLCs. GE's ToolboxST covers GE Mark VIe turbine controllers. Schneider Electric's EcoStruxure covers Modicon PLCs. Each has its own project file format, but they share the same property: the project file documents the intended process behaviour, which makes it the template for any modification.

Engineering credentials are often stored in project files, in Windows Credential Manager, or in plain text configuration files. The default passwords for PLCs shipped by vendors are widely documented. Password policies for PLC access are frequently absent or unenforced.

## Historian servers

Historians collect time-series process data from SCADA systems and store it for operational analytics, reporting, and maintenance planning. OSIsoft PI (now AVEVA PI System) is the market-leading historian and is present in a large proportion of industrial environments. Aspentech IP.21, Honeywell Uniformance, and similar products fill the same role.

Historian servers sit at the IT/OT boundary and have bidirectional connectivity: they receive data from Level 2 SCADA servers and expose it to corporate IT for reporting and analytics. This makes them both a reconnaissance target (reading all process data in cleartext) and a pivot point (using the historian's connectivity to reach Level 2 systems it communicates with).

OSIsoft PI's AF server and the PI Web API expose a REST interface over HTTP or HTTPS. Unauthenticated access, or access with default credentials, exposes the complete tag database and all historical process data.

## HMI servers and SCADA software

SCADA HMI servers run Windows-based supervisory software: Wonderware InTouch (now AVEVA InTouch), Ignition, FactoryTalk View, and similar. These are Windows hosts in the Level 2 network with direct communication paths to PLCs. They run software that requires specific Windows versions and configurations, which often means outdated OS versions, disabled Windows Defender, and limited patching.

Remote desktop access to a SCADA HMI server provides access to its SCADA software interface, which in turn provides access to the controlled process. This does not require exploiting any PLC vulnerability; the operator interface is designed to send commands to PLCs, and an attacker with RDP access to the HMI server has the same capabilities as the operator sitting in front of it.

## The deployment chain

Engineering workstation compromise enables the full attack chain:

The attacker opens the existing project file to understand the current logic and identify which function blocks control which process outcomes. They modify specific function blocks to introduce the desired behaviour change: altered setpoints, modified interlocks, disabled safety checks, or added conditional logic that triggers under specific circumstances. They download the modified project to the target PLC using the same deployment procedure the engineer uses. To the PLC, the download is indistinguishable from a legitimate maintenance activity. The change takes effect immediately.

If the modification is designed to be subtle, the previous behaviour is preserved for all conditions that would be monitored, and the changed behaviour is triggered only by conditions the attacker controls. The SCADA system continues to report normal operation because it reads the same data it always has.
