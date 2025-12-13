# Asset inventory and mapping

Knowing what's there before you accidentally turn it off.

By now you've done extensive passive and active reconnaissance. You've captured traffic, scanned networks, identified devices, tested services, and documented findings. You have notebooks full of observations, packet captures measured in gigabytes, and screenshots of every web interface you could find.

Now comes the unglamorous but absolutely critical work of organising this information into comprehensive asset inventory and maps. This isn't just paperwork for the sake of paperwork. It's what prevents you from accidentally testing the wrong system, helps you understand attack paths, and provides the foundation for risk assessment and remediation planning.

It's also frequently the most valuable deliverable for the client. Many OT organisations don't have accurate asset inventories. They know roughly what they have ("three turbine PLCs, some network switches, a SCADA server somewhere"), but comprehensive documentation is often outdated, incomplete, or non-existent. Your reconnaissance provides them with current, accurate information about their own environment, which is sometimes worth more than the vulnerability findings.

## Creating comprehensive asset registers

An asset register is a structured list of every device, system, and component in the environment. It's the foundation of everything else you'll do.

### Essential fields for each asset

Every asset entry should include identification information at minimum. Asset ID is a unique identifier you assign (TURB-PLC-01, SCADA-SRV-01, etc.). Hostname or device name as configured in the device. IP address, noting whether it's static or DHCP. MAC address for definitive identification. Physical location (Turbine Hall Rack 3, Control Room Server Closet, Substation 7). Asset owner or responsible party (OT Engineering Manager, Operations, Facilities).

Classification fields help prioritise and organise. Asset type categorises broadly (PLC, HMI, RTU, server, workstation, network device). Criticality rates importance (critical, high, medium, low). Environment specifies context (production, development, test, decommissioned but still powered on for some reason).

Technical details provide the information you need for vulnerability assessment. Manufacturer and model number. Serial number if available. Firmware or software version. Operating system if applicable. Protocols supported. Open ports and services discovered during scanning.

Operational details explain what the asset actually does. Purpose or function in plain language ("controls turbine 1 speed and output"). Operational state (active, standby, offline, in maintenance). Maintenance schedule if documented. Last known maintenance date. Vendor support status (under contract, out of warranty, end-of-life and unsupported).

Security details document the current security posture. Known vulnerabilities from your reconnaissance. Patch status (up to date, behind by X patches, unpatchable). Authentication methods in use. Whether it's exposed to internet directly or indirectly. Remote access capabilities and methods.

### Asset register formats

The simplest and most common format is a spreadsheet. Excel or Google Sheets work fine. Create columns for all the fields above. Use one sheet per asset type (PLCs, HMIs, servers, etc.) or one comprehensive sheet with filtering. Spreadsheets are easy to create, easy to share, easy to update, and everyone knows how to use them.

For larger environments, a proper database provides better functionality. SQLite for simple local database. PostgreSQL or MySQL for multi-user access. Allows complex queries, relationships between assets, and programmatic access. More powerful but requires more setup and maintenance.

Commercial asset management platforms like [CyberX](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-iot) (now Microsoft Defender for IoT), [Claroty](https://claroty.com/), or [Nozomi Networks](https://www.nozominetworks.com/) provide automated asset discovery, continuous monitoring, and integration with other security tools. They're expensive but comprehensive. They can passively monitor networks and automatically build asset inventories. They're particularly valuable for large or complex environments.

At UU P&L, the initial asset register started as a spreadsheet because that's what was immediately available and didn't require procurement approval. It looked something like this:


| Asset ID    | Hostname       | IP            | Type        | Manufacturer | Model          | Firmware | Criticality |
|-------------|----------------|---------------|-------------|--------------|----------------|----------|-------------|
| TURB-PLC-01 | TURB-PLC-01    | 192.168.10.10 | PLC         | Siemens      | S7-315-2PN/DP  | V3.2.6   | Critical    |
| TURB-PLC-02 | TURB-PLC-02    | 192.168.10.11 | PLC         | Siemens      | S7-315-2PN/DP  | V3.2.6   | Critical    |
| TURB-PLC-03 | TURB-PLC-03    | 192.168.10.12 | PLC         | Siemens      | S7-315-2PN/DP  | V3.2.6   | Critical    |
| SAFE-PLC-01 | SAFE-PLC-01    | 192.168.10.20 | Safety PLC  | Siemens      | S7-400FH       | V6.0.3   | Critical    |
| SCADA-PRI   | SCADA-PRIMARY  | 192.168.20.5  | Server      | HP           | ProLiant DL380 | N/A      | Critical    |
| HMI-01      | HMI-CONTROL-01 | 192.168.20.11 | HMI         | Dell         | OptiPlex 7040  | N/A      | High        |
| ENG-WS-01   | ENG-WS-01      | 192.168.40.15 | Workstation | Dell         | Latitude 7490  | N/A      | High        |
| UNKNOWN-01  | Unknown        | 192.168.10.99 | Unknown     | Unknown      | Unknown        | Unknown  | Unknown     |


The "UNKNOWN-01" entry was the Windows XP machine discovered during reconnaissance. It needed investigation before proper categorisation.

### Dealing with unknowns

Every reconnaissance finds unknown assets. Things not in documentation, not in configuration management databases, not known to current staff. The "temporary" solutions from years ago that became permanent. The contractor equipment that was never removed. The test systems that somehow made it to production.

The process for handling unknowns is methodical. First, document what you know. Record IP address, MAC address, any observed behaviour, open ports, any responses from probes. Even partial information is better than nothing.

Second, investigate further with careful probing. Can you safely connect to it? Does it respond to ping? To any protocols? Is there a web interface? Can you identify the operating system?

Third, consult with staff. Someone might remember it. "Oh, that old thing? Yeah, I think John set that up back in 2008 before he retired." This is why institutional knowledge is so valuable and why staff turnover is so problematic in OT environments.

Fourth, review historical records. Old documentation, archived emails, maintenance logs, procurement records, anything that might mention this device or its IP address.

Fifth, if it's still unknown and safe to do so, physical inspection can be revealing. Look at it. What does it physically look like? Are there labels? Model numbers? Cables connected to it? Sometimes the only way to know what a mystery box does is to look at the mystery box.

At UU P&L, the unknown Windows XP machine investigation revealed layers of archaeology. MAC address vendor lookup identified it as a Dell system. Port scan showed Windows XP SP2 signatures. SMB enumeration revealed hostname "TURBINE-DATA-01" and accessible file shares containing CSV files with turbine operational data going back to 1998.

Consultation with maintenance staff produced this exchange:

"Do you know what TURBINE-DATA-01 is?"

"Oh, that old thing? Yeah, it collects data from the turbines."

"Is it important?"

"I guess? We look at those logs sometimes when troubleshooting."

"Who maintains it?"

"Nobody, really. It just runs."

"What happens if it stops running?"

"I dunno. Nobody's ever turned it off to find out."

This is terrifyingly common in OT. Critical functionality running on forgotten hardware that nobody dares touch because nobody knows what will break if they do.

The system was eventually identified as a legacy data logger installed with the original turbines in 1998. It polls turbine data via serial connections, logs to CSV files, and makes those files available via SMB shares. The turbine manufacturer is long out of business. The software is irreplaceable. Nobody has installation media. Nobody knows the administrator password. It's become load-bearing infrastructure through sheer persistence.

The asset register entry was updated:

```
Asset ID: DATA-LOG-01 (formerly UNKNOWN-01)
Purpose: Legacy turbine data logger, polls serial data, stores CSV files
Criticality: High (no replacement available, used for troubleshooting)
Risks: Windows XP, unpatched since 2008, no authentication on file shares
Recommendations: Isolate on separate VLAN, read-only network share, backup data regularly, investigate replacement options
```

### Handling decommissioned but powered-on assets

Another common discovery is systems that are supposedly decommissioned but still powered on and connected to the network. These are dangerous because they're not monitored, not maintained, and often not secured, but they might still be doing something important that nobody remembers.

At UU P&L, a system labeled "OLD-SCADA" was listed in documentation as "decommissioned 2018". Yet it was responding to pings and had active network connections.

Investigation revealed it was the previous SCADA server, replaced in 2018 but never actually shut down. It was still running. It still had connections to some RTUs that hadn't been migrated to the new SCADA system. Operators occasionally used it to check historical data from before the migration.

Shutting it down would have broken those RTU connections and eliminated access to historical data. But keeping it running meant maintaining an obsolete, unpatched Windows Server 2003 system with known vulnerabilities.

The recommendation was gradual migration: identify all RTUs still connected to old SCADA, migrate them to new SCADA one by one, archive historical data to the new historian, then finally decommission the old system properly.

This took six months because each RTU migration required testing and coordination with operations. But at the end, the old SCADA server was finally, actually decommissioned (powered off, network cables removed, physically removed from the rack). Until then, it remained in the asset register with appropriate warnings.

## Firmware and software versions

Tracking firmware and software versions is critical for vulnerability management. This information should be in the asset register, but it also deserves dedicated documentation because versions change over time (or should change, if patching happens).

### Version tracking spreadsheet

Create a separate tracking sheet for versions:

| Asset ID    | Component | Current Version | Latest Version  | Last Updated | Patch Status            |
|-------------|-----------|-----------------|-----------------|--------------|-------------------------|
| TURB-PLC-01 | Firmware  | V3.2.6          | V3.3.18         | 2019-03-15   | 24 versions behind      |
| SCADA-PRI   | OS        | Win Server 2012 | Win Server 2022 | 2015-06-20   | 2 major versions behind |
| SCADA-PRI   | InTouch   | 2014 R2 SP1     | 2023 R2         | 2015-06-20   | 9 years behind          |
| HMI-01      | OS        | Windows 7       | Windows 11      | 2016-08-10   | End of life             |

This makes it immediately obvious which systems are current, which are behind, and which are catastrophically out of date.

### Known vulnerabilities by version

Cross-reference versions with vulnerability databases. For each version, document known CVEs, their severity, whether exploits are publicly available, and whether patches are available.

At UU P&L, this revealed that every single PLC had multiple critical vulnerabilities, the SCADA server had 23 known vulnerabilities ranging from medium to critical, and the Windows 7 HMI systems had hundreds of known vulnerabilities (because Windows 7 has been end-of-life since January 2020).

### Why things don't get patched

Understanding why systems remain unpatched is important for realistic recommendations. At UU P&L, the reasons included:

"Patching might break things." This is the most common reason and it's not entirely unfounded. OT systems are often fragile integrations of multiple vendor products. Patches from one vendor can break compatibility with another vendor's products. Testing patches requires downtime and comprehensive validation.

"We can't afford the downtime." Patching often requires rebooting systems. In 24/7 operations, finding downtime is difficult. At UU P&L, turbines run continuously except for scheduled maintenance every six months.

"The vendor says patching voids warranty." Some vendor support contracts specify that only the vendor can apply patches, or that patches must be vendor-approved. Applying patches independently can void support.

"We tested patches and they broke things." Sometimes patches do break things. When UU P&L tested a Siemens firmware update on a spare PLC, it changed the behaviour of certain timing functions in a way that would have affected turbine control logic. The patch was abandoned.

"Nobody knows how to patch this." For older systems, the knowledge of how to apply patches may have left with retired staff.

"The system is end-of-life, no patches exist." Windows XP, Windows 7, older PLC firmware, obsolete SCADA software. No patches are being developed anymore.

These aren't excuses, they're real operational constraints. The security team's job is to understand these constraints and recommend realistic mitigations when patching isn't possible, such as network segmentation to limit exposure, enhanced monitoring to detect exploitation attempts, or compensating controls like application whitelisting.

## Network segmentation analysis

Network segmentation is supposed to limit the blast radius of compromises. In theory, the corporate network is separate from OT, control systems are separate from safety systems, and different operational zones are separated from each other.

In practice, segmentation is often more theoretical than real.

### Analysing actual segmentation

Don't trust network diagrams. They show how things are supposed to be, not how they actually are. Your reconnaissance revealed the truth. Now document it.

Create a segmentation analysis showing what can actually talk to what:

| Zone            | Can Reach      | Should Reach     | Problem?                       |
|-----------------|----------------|------------------|--------------------------------|
| Corporate IT    | OT Engineering | No direct access | Jump box bypasses segmentation |
| Corporate IT    | SCADA Network  | No direct access | Historian bridges networks     |
| OT Engineering  | All PLCs       | Yes              | OK                             |
| OT Engineering  | Safety PLCs    | No               | PROBLEM: No isolation          |
| Control Network | Safety Network | Emergency only   | PROBLEM: Same physical VLAN    |


At UU P&L, the segmentation analysis revealed that whilst VLANs existed, the firewall between them had rules that effectively allowed all traffic. The segmentation was cosmetic. Everything could talk to everything.

The jump box that was supposed to be the controlled access point had RDP open from the corporate network with shared credentials, making it effectively transparent rather than a controlled chokepoint.

The historian database sat on the corporate network but had direct connections to SCADA systems on the OT network, creating a bridge.

The wireless access point in the turbine hall was connected to both the corporate VLAN and the turbine control VLAN, completely bypassing intended segmentation.

### Segmentation recommendations

Based on actual observed connectivity, recommend segmentation improvements:

Immediate fixes (low cost, high impact): Remove the wireless access point bridging networks. Fix firewall rules to actually enforce segmentation. Disable unnecessary network connections.

Short term (moderate cost, moderate effort): Implement proper jump host architecture with authentication and monitoring. Isolate safety systems on physically separate network. Deploy data diode or unidirectional gateway for historian data collection.

Long term (high cost, major project): Redesign network architecture following Purdue model. Implement proper DMZs. Deploy industrial firewalls with deep packet inspection for OT protocols.

At UU P&L, the immediate fixes were implemented within weeks (because they cost nothing but configuration changes). The short-term improvements were budgeted for the next fiscal year. The long-term redesign was added to the five-year capital plan, which is consultant-speak for "maybe someday if budget appears and priorities don't change".

## Trust boundary identification

Trust boundaries are the points where different levels of trust meet. Understanding these boundaries is critical for security architecture and attack path analysis.

### Common trust boundaries in OT

Internet to DMZ boundary is the perimeter facing the public internet. Should be heavily defended with firewalls, intrusion detection, and strict access controls.

DMZ to corporate IT boundary separates the demilitarised zone from the internal corporate network. Should verify authentication and authorization.

Corporate IT to OT boundary is one of the most critical. Corporate networks have different threat profiles than OT networks (more users, more internet access, more malware). This boundary should be strictly controlled.

OT engineering to production control boundary separates engineering/programming networks from operational control systems. Engineering workstations have elevated privileges and should be isolated from routine operations.

Control to safety boundary is critical for safety-critical industries. Safety systems must remain functional even if control systems are compromised.

Production to test/development boundary prevents test systems from affecting production.

### Trust boundary mapping at UU P&L

Mapping trust boundaries revealed several boundaries that should exist but didn't:

Corporate IT to OT Engineering should have been a strict boundary with authentication and monitoring. In reality, it was crossed by multiple systems: the historian, the jump box with shared credentials, the wireless access point, and the mysterious VPN that IT had installed without telling OT.

OT Engineering to Production Control should have limited which systems could program PLCs. In reality, any system on the engineering network could connect to any PLC.

Control to Safety boundary theoretically separated safety PLCs from control PLCs. In reality, they were on the same VLAN with no isolation.

### Trust boundary violations

Document every case where trust boundaries are violated. Each violation is a potential attack path.

At UU P&L, the most serious violation was the safety PLC on the same network as control PLCs. An attacker who compromised a control PLC could potentially communicate with safety PLCs, which should never be possible.

The wireless access point violated multiple boundaries simultaneously. It connected corporate and OT networks, bypassing all intended security controls.

The engineering workstation with file sharing enabled violated the principle that engineering tools should not be accessible from untrusted networks.

### Recommendations for trust boundaries

For each violated trust boundary, recommend remediation. At minimum, make the boundary visible with logging and monitoring even if you can't immediately enforce it properly. Better, implement authentication and authorization at the boundary. Best, implement proper segmentation with firewalls and possibly data diodes.

## Data flow mapping

Understanding how data flows through the environment reveals dependencies, potential bottlenecks, and attack paths.

### Types of data flows

- Control data flows from SCADA to PLCs, from operators to process equipment. This is the most time-sensitive and critical data.
- Monitoring data flows from PLCs to SCADA, from sensors to displays. Continuous polling, high volume, but generally one-way.
- Engineering data flows when programming PLCs, updating configurations, or downloading logs. Sporadic but privileged access.
- Historical data flows from operational systems to historians and databases. Used for trending, analysis, and reporting.
- Business data flows from OT systems to corporate IT for reporting, billing, inventory management, and business intelligence.
- Remote access data flows when vendors or engineers connect remotely. Should be carefully controlled but often isn't.

### Mapping data flows

Create diagrams showing who talks to whom, what protocols they use, what data they exchange, and how frequently:

```
SCADA Server (192.168.20.5)
  → Polls PLC 1 (192.168.10.10) via Modbus every 5 seconds
  → Polls PLC 2 (192.168.10.11) via Modbus every 5 seconds
  → Polls PLC 3 (192.168.10.12) via Modbus every 5 seconds
  → Sends commands via Modbus when operator issues control actions
  
Historian (192.168.30.5)
  → Queries SCADA Server via proprietary protocol every 5 minutes
  → Stores data in SQL Server database
  → Serves data to Business Intelligence tools via ODBC
  
Engineering Workstation (192.168.40.15)
  → Connects to any PLC via S7comm when programming
  → Uploads/downloads PLC programs (megabytes transferred)
  → Occurs during maintenance windows, not continuously
```

Looking something like:

SCADA ↔ PLC communications (continuous control traffic):

![SCADA ↔ PLC communications (continuous control traffic)](/_static/images/ot-scada-plc-communications.png)

Historian ↔ SCADA ↔ Business systems (periodic data flow)

![Historian ↔ SCADA ↔ Business systems (periodic data flow) 1](/_static/images/ot-historian-scada-business1.png)

And:

![Historian ↔ SCADA ↔ Business systems (periodic data flow) 2](/_static/images/ot-historian-scada-business2.png)

Engineering workstation ↔ PLCs (maintenance-only, very noisy)

![Engineering workstation ↔ PLCs (maintenance-only, very noisy)](/_static/images/ot-engineering-plc.png)

At UU P&L, data flow mapping revealed several surprises. The business intelligence system on the corporate network was directly querying the historian every minute, not the expected hourly schedule. This caused occasional performance issues when BI queries coincided with high data collection periods.

The old Windows XP data logger was pushing CSV files to a network share that nobody knew about. The share was on the SCADA server. The SCADA server was running periodic batch jobs to parse these CSV files, a process that consumed significant CPU and occasionally caused SCADA response lag.

An undocumented data flow existed between the corporate network and a PLC. Investigation revealed it was an automated script that queried PLC status for display on the corporate website's "facility status" page. This gave public internet users real-time information about turbine operations, which was interesting from a transparency perspective but concerning from a security perspective.

## Critical path analysis

Critical path analysis identifies which systems and connections are essential for continued operation. If something on the critical path fails, operations stop.

### Identifying critical paths

For each operational function, trace the dependencies from physical process back to the systems that monitor and control it.

Turbine 1 operation depends on Turbine 1 PLC, SCADA server polling PLC, HMI displaying data to operators, network connecting PLC to SCADA, switch in turbine hall, network cable from turbine hall to control room, and power supply to all of the above.

A failure at any point in this chain affects turbine operation. This is the critical path.

At UU P&L, critical path analysis revealed single points of failure:

The core network switch in the control room carried all OT traffic. If it failed, SCADA lost connection to all PLCs across the facility. This switch was 12 years old, out of warranty, and no replacement was on hand. It became a critical liability.

The SCADA server was a single point of failure for operator visibility. The backup SCADA server existed but automatic failover wasn't configured. Manual failover took 10-15 minutes during which operators had no visibility into turbine status.

The historian was a single point of failure for data collection. If it failed, operational data was lost permanently. Backups existed but only of the database itself, not the active collection process.

### Critical path documentation

For each critical system, document what it's critical to, what it depends on, what depends on it, estimated impact of failure (loss of visibility, loss of control, safety impact), and estimated time to recovery.

```
System: SCADA Server
Critical to: Operator visibility, remote control, alarm management
Depends on: Network connectivity, SQL database, historical logs
Depended on by: All HMIs, alarm systems, engineering workstations
Failure impact: Loss of operator visibility, no remote control (local control still possible at turbines)
Time to recovery: 15 minutes (manual failover to backup) or 4 hours (rebuild if backup also fails)
Backup status: Backup server exists but requires manual failover
```

This documentation is invaluable during incident response. When something fails at 3 AM, having pre-documented critical paths and recovery procedures saves precious time.

## Dependency documentation

Dependencies are the hidden connections between systems. System A depends on System B, which depends on System C, and nobody documents these relationships until something breaks.

### Types of dependencies

Technical dependencies are the obvious ones. SCADA depends on network connectivity to PLCs. PLCs depend on power supplies. HMIs depend on SCADA server.

Operational dependencies are less obvious. The turbine startup sequence depends on specific order of operations. The maintenance schedule depends on weather forecasts (can't shut down turbines during peak demand caused by heat waves). The alarm system depends on operator response protocols.

Data dependencies are subtle. The business intelligence dashboard depends on data from the historian, which depends on data from SCADA, which depends on PLCs. If any link in this chain breaks, BI reports become stale.

Timing dependencies are critical in real-time systems. The PLC scan cycle depends on completing within 50 milliseconds. Network polling depends on devices responding within timeout periods. Automated sequences depend on actions completing before the next action begins.

### Discovering hidden dependencies

The only reliable way to discover dependencies is to watch what happens when things break. Unfortunately, this usually happens accidentally rather than during controlled testing.

At UU P&L, several hidden dependencies were discovered the hard way:

When a network switch was rebooted for maintenance, the SCADA server lost connection to PLCs as expected. However, it also triggered an automatic email alert to the city emergency services (undocumented feature from years ago) which caused unnecessary panic.

When the historian database filled its disk space, data collection stopped as expected. However, the SCADA server's alarm logging also failed (stored in same database, different schema) which meant critical alarms weren't being recorded. This went unnoticed for three days until an audit questioned why alarm logs were empty.

When the engineering workstation was rebooted, a scheduled task stopped running. This task was polling a legacy serial device and forwarding data to SCADA. The device was the pump controller connected via the Raspberry Pi. Without this task, pump status wasn't updated in SCADA. Operators noticed unusual pump behavior and investigated, discovering the dependency nobody had documented.

### Dependency mapping

Create dependency maps showing what depends on what:

```
Turbine Operation
├─ Turbine PLC
│  ├─ Power Supply
│  ├─ Network Connection
│  └─ PLC Program (stored in PLC)
├─ SCADA Server
│  ├─ Power Supply  
│  ├─ Network Connection
│  ├─ SQL Database
│  └─ SCADA Software License
├─ HMI
│  ├─ Power Supply
│  ├─ Network Connection
│  └─ Windows 7 OS
└─ Network Infrastructure
   ├─ Control Room Switch
   ├─ Turbine Hall Switch
   ├─ Network Cables
   └─ Power to Switches
```

This seems obvious when written down, but these relationships are often undocumented. During incident response, having this map saves time tracing dependencies.

### Circular dependencies

Watch for circular dependencies where A depends on B which depends on A. These create deadlock scenarios where neither system can start without the other.

At UU P&L, a subtle circular dependency existed: the SCADA server time synchronization depended on the network time server, which was on the corporate network. The corporate network firewall rules allowed time sync only from authenticated sources. The SCADA server's authentication to corporate network services depended on correct time (Kerberos). If SCADA server time drifted too far, it couldn't authenticate to get time synchronization, creating a deadlock.

The solution was adding a local time server on the OT network, breaking the dependency on corporate IT.

## The comprehensive picture

After completing asset inventory, version tracking, segmentation analysis, trust boundary identification, data flow mapping, critical path analysis, and dependency documentation, you have a comprehensive picture of the environment.

This documentation serves multiple purposes. It's the foundation for vulnerability analysis and risk assessment. It guides remediation planning and prioritization. It supports incident response and troubleshooting. It helps with change management and impact analysis. Most importantly, it gives the organization accurate knowledge of their own environment.

At UU P&L, the most valuable outcome wasn't the list of vulnerabilities (though that was important). It was the accurate, current documentation of what actually existed. The network diagrams showed reality, not theory. The asset inventory included the forgotten systems. The dependency maps revealed hidden connections.

The facilities manager summarised it well during the final presentation: "For the first time in ten years, we actually know what we have and how it all connects. That alone was worth the cost of the assessment."

### The discovery that made everyone pause

The comprehensive mapping revealed one particularly concerning finding that hadn't been obvious during reconnaissance. The turbine emergency shutdown system, which is supposed to be the ultimate safety mechanism, had a dependency chain that made everyone in the room uncomfortable.

The emergency shutdown system depended on the safety PLC, which depended on network connectivity to the SCADA server for status reporting, which depended on the control room network switch, which depended on its configuration stored on a TFTP server, which was the Windows XP machine also hosting the cafeteria menu website.

Yes, the cafeteria menu website. Someone years ago had needed a simple web server for posting the weekly menu. The Windows XP machine was available. A web server was installed. The menu site was created. Later, when the network team needed a TFTP server for backing up switch configurations, the XP machine was convenient and already on the network.

The cafeteria menu website accidentally became a critical dependency for the emergency shutdown system. If the XP machine failed, switch configurations couldn't be restored after power loss, SCADA couldn't reconnect to safety systems, and the emergency shutdown status monitoring would be degraded.

Nobody had planned this dependency. It had emerged organically through a series of small, reasonable decisions that created an unreasonable outcome. This is how OT environments work: temporary solutions become permanent, convenience trumps architecture, and mission-critical functions end up depending on systems that also serve lunch menus.

The recommendation was unambiguous: isolate the safety system dependencies, deploy a proper configuration management system, and for the love of all that is sacred, separate the cafeteria menu from the emergency shutdown infrastructure.

The cafeteria menu was migrated to a proper corporate web server within a week. The switch configuration management took six months because it required coordination, testing, and procurement of proper infrastructure.

But at least nobody had to explain to the Patrician that a power outage was prolonged because the cafeteria menu website was down.
