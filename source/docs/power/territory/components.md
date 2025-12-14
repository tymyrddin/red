# Key components

Walking into a control room for the first time can be overwhelming. There are screens everywhere, cabinets full of 
equipment with blinking lights, cables running in directions that seem to defy both logic and gravity, and a 
persistent low hum that suggests everything is either working perfectly or about to explode.

We need to know which components do what, how they connect, and which ones we absolutely must not touch without 
triple-checking our rules of engagement.

Touring the key components we can encounter, using examples from Unseen University Power & Light Co., where the 
equipment ranges from "surprisingly modern" to "archaeological artifact that somehow still functions".

## PLCs, the brains with no sense of self-preservation

![PLCs](/_static/images/ot-plcs.png)

Programmable Logic Controllers (PLCs) are the workhorses of industrial automation. They're ruggedised computers 
designed to run control programs in harsh environments (temperature extremes, vibration, electrical noise, and at 
UU P&L, occasional magical interference).

### What PLCs do

A PLC continuously executes a control program in a loop called a scan cycle:

1. Read inputs (sensors, switches, other devices)
2. Execute logic (ladder logic, function blocks, structured text)
3. Update outputs (valves, motors, indicators)
4. Handle communications
5. Repeat, typically every 10-100 milliseconds

This program implements the control strategy. If temperature exceeds setpoint, open cooling valve. If pressure drops below threshold, start backup pump. If the Librarian's banana supply drops below three bunches, trigger urgent restocking alarm.

### PLC architecture

PLCs consist of:
- CPU module (runs the program)
- Power supply
- I/O modules (digital inputs/outputs, analog inputs/outputs)
- Communication modules (Ethernet, serial, fieldbus)
- Programming port (for connecting engineering software)

Modern PLCs are modular. You can add I/O modules as needed. Older PLCs might be monolithic units with fixed I/O.

### Common PLC manufacturers

- Siemens (S7-300, S7-400, S7-1200, S7-1500)
- Allen-Bradley/Rockwell Automation (ControlLogix, CompactLogix, MicroLogix)
- Schneider Electric (Modicon)
- Mitsubishi (MELSEC)
- ABB
- Omron
- GE (now Emerson)

At UU P&L, the turbine control system uses Allen-Bradley ControlLogix PLCs from 1998. The alchemical reactor uses 
Siemens S7-400 PLCs from 2003. The Library environmental system uses a Schneider Modicon from 1987 that predates 
the concept of network connectivity (someone added a Modbus gateway in 2005).

### Security characteristics of PLCs

PLCs were designed assuming physical security. If you have physical access to program the PLC, you're assumed to be authorised. This assumption extended to network access once PLCs gained Ethernet connectivity.

Most PLCs have minimal security:
- No authentication, or weak authentication (fixed passwords, no password policy)
- No encryption of communications
- No audit logging of who changed what
- No protection against malicious logic
- No code signing or verification
- Physical key switches (which are often left in "Run" or "Program" mode)

Newer PLCs are better. The Siemens S7-1500 series supports password protection, access levels, and encrypted connections. The Rockwell ControlLogix v21 and later supports role-based access control and secure connections. But adoption is slow, and backwards compatibility often means security features are disabled.

### Testing PLCs

When pentesting, your interaction with PLCs should be extremely cautious:

1. Identification: Use passive reconnaissance or very gentle active scanning to identify PLC models, firmware versions, and communication protocols. Tools like [plcscan](https://github.com/yanlinlin82/plcscan) can identify PLCs without being overly aggressive.

2. Enumeration: Query the PLC for its configuration, program, and current state. Most PLCs will happily tell you everything about themselves if you ask politely. Use vendor tools or protocol libraries like [Snap7](http://snap7.sourceforge.net/) for Siemens or [pycomm3](https://github.com/ottowayi/pycomm3) for Allen-Bradley.

3. Analysis: Download the PLC program (if possible and authorised). Analysing the logic offline to understand what the system does and identify potential vulnerabilities in the control logic itself. Tools like [PLCinject](https://github.com/SCADACS/PLCinject) can help analyse PLC programs.

4. Testing: Any write operations (changing values, uploading programs, forcing outputs) should only be done in controlled test environments, never on production systems during initial pentest.

At UU P&L, testing the turbine PLCs revealed:
- No password protection on the programming port
- Ability to download the complete control program via Ethernet
- Ability to read/write any memory location
- No logging of programming access
- Physical key switch left in "Remote" mode, allowing remote program changes

The recommendation wasn't "fix the PLC" (impossible without replacement). It was "segment the network so only engineering workstations can reach PLC programming ports, monitor for unexpected PLC communications, implement authentication at the network layer."

## RTUs, the distant cousins

![RTU](/_static/images/ot-rtu.png)

Remote Terminal Units (RTUs) are similar to PLCs but designed specifically for remote monitoring and control over 
large geographic areas. They're common in utilities (power, water, oil/gas pipelines) where you need to monitor and 
control equipment spread across cities or countries.

### RTU characteristics

RTUs are designed for:
- Remote locations (unmanned substations, pump stations, pipeline monitoring points)
- Harsh environments
- Autonomous operation (they keep working even if communications fail)
- Low power consumption (some run on solar power and batteries)
- Communication over various media (serial radio, cellular, satellite)

RTUs collect data from sensors, perform basic control logic, buffer data during communication outages, and communicate with a central SCADA system using protocols like DNP3, Modbus, or IEC 60870-5-104.

At UU P&L, RTUs are deployed at electrical substations throughout Ankh-Morpork. Each RTU monitors circuit breaker 
status, transformer load, voltage levels, and can remotely operate breakers when commanded by the central SCADA system.

### Security challenges with RTUs

RTUs present unique security challenges:
- Physical security is often minimal (a locked cabinet in an unmanned building)
- Communication links might be wireless (radio, cellular, satellite)
- They're exposed to public networks (cellular networks aren't trusted)
- They run for years without intervention
- Firmware updates are difficult (requires site visits or risky remote updates)

Testing RTU security requires:
- Understanding the communication protocols
- Testing for weak authentication
- Analysing the security of communication links
- Assessing physical security (during site visits)
- Evaluating the security of remote management interfaces

At UU P&L, the RTUs communicate with central SCADA via DNP3 over cellular connections. Testing revealed:
- No DNP3 authentication enabled
- No VPN or encryption on cellular links
- Default SNMP community strings (allowing remote configuration changes)
- Web interfaces for local configuration with default passwords
- No detection of unauthorised access

An attacker with access to the cellular network could potentially send DNP3 commands to operate circuit breakers. The recommendations included implementing DNP3 Secure Authentication, using VPNs for all RTU communications, changing default credentials, and deploying intrusion detection.

## HMIs, where humans meet machines

![HMI](/_static/images/ot-hmi.png)

Human-Machine Interfaces (HMIs) are the screens that operators use to monitor and control processes. They display pretty graphics of the plant, show real-time values, and provide buttons for controlling equipment.

HMIs range from simple touch panels to full SCADA workstations running sophisticated software.

### HMI software

Common HMI platforms include:
- Siemens WinCC
- Rockwell FactoryTalk View
- Wonderware InTouch
- Ignition by Inductive Automation
- Schneider Vijeo Citect
- GE iFIX

These applications run on Windows (almost always Windows). They connect to PLCs and other devices, retrieve data, send commands, log events, and provide the user interface for operations.

### HMI architecture

An HMI system typically consists of:
- HMI software application
- Database (for storing configurations, logs, historical data)
- Communication drivers (for talking to PLCs)
- Web server (many HMIs provide web-based remote access)
- User authentication system (in theory)

At UU P&L, the main SCADA HMI runs Wonderware InTouch on Windows 7. There are also several Panel PCs (industrial 
touchscreen computers) running simpler HMI applications locally at each substation.

### Security characteristics of HMIs

HMIs are often the weakest link in OT security. They're typically:
- Running on Windows (with all the associated vulnerabilities)
- Running outdated operating systems (Windows XP, Windows 7, Server 2003)
- Not patched (can't risk breaking the HMI application)
- Accessible from corporate networks (operators need access)
- Running web servers with default credentials
- Storing credentials in plaintext configuration files
- Using hardcoded database passwords
- Providing remote access with weak authentication

Many HMI applications were developed when security wasn't a concern. They might store passwords in plaintext in XML configuration files, use SQL Server with 'sa' account and blank password, or provide web interfaces with default credentials that can't be changed.

### Testing HMIs

HMI security testing is more like traditional IT application testing:

1. Web interface testing: Many HMIs provide web access. Test for common web vulnerabilities (SQL injection, XSS, authentication bypass, directory traversal). Tools like [Burp Suite](https://portswigger.net/burp) and [OWASP ZAP](https://www.zaproxy.org/) work well here.

2. Credential testing: Try default credentials (documented in security advisories and [industrial control systems default passwords](https://github.com/scadastrangelove/SCADAPASS)). Check configuration files for hardcoded credentials. And even though scadapass is from 2016, these credentials remain.

3. File system analysis: If you can access the HMI filesystem (via web vulnerabilities or legitimate access), look for configuration files, project files, and backups that might contain sensitive information.

4. Network service enumeration: HMIs often run multiple services (RDP, VNC, web servers, database servers). Enumerate these services and test their security.

5. Database testing: If the HMI uses a database, test database security. Many use SQL Server or MySQL with weak credentials.

At UU P&L, testing the main SCADA HMI revealed:

The web interface (running on IIS) had a directory traversal vulnerability allowing access to configuration files. These configuration files contained:
- Database credentials in plaintext
- PLC IP addresses and communication settings  
- User passwords in reversible encryption (XOR with a fixed key)

The web interface had default credentials (admin/admin) that worked because "the vendor said changing them might affect licensing, and we don't want to risk it".

The HMI Windows machine itself had RDP enabled, accessible from the corporate network, with the local Administrator account using "Password123" (required by the HMI software vendor, apparently).

The recommendations included:
- Patching the directory traversal vulnerability (required vendor support)
- Changing default credentials
- Implementing proper password management
- Restricting RDP access
- Network segmentation to limit who can access HMI systems
- Encrypting credentials in configuration files (required vendor cooperation)

The university's response was to implement the network segmentation (relatively easy) and change the obvious passwords (grudgingly). The rest was categorised as "long-term improvements requiring budget and vendor engagement".

## SCADA servers and historians

![SCADA](/_static/images/ot-scada.png)

SCADA (Supervisory Control and Data Acquisition) servers are the central systems that collect data from PLCs and RTUs, present it to operators via HMIs, log events, and manage the overall industrial process.

### SCADA system architecture

A typical SCADA system includes:
- SCADA server (runs the core SCADA software)
- Historian (stores time-series data for long-term analysis)
- HMI workstations (for operators to interact with the system)
- Engineering workstations (for configuring and maintaining SCADA)
- Communication servers (for protocol conversion and gateway functions)
- Application servers (for advanced analytics, reporting, etc.)

At UU P&L, the SCADA infrastructure includes:
- Primary and backup SCADA servers running Wonderware System Platform
- Historian server storing 10 years of operational data
- Four operator workstations in the central control room
- Two engineering workstations (one in the office, one mobile for field work)

### Historians deserve special attention

Historians are databases optimised for storing time-series data from industrial processes. They record every sensor reading, every operator action, every alarm, typically at resolutions from milliseconds to seconds, for years.

This data is valuable for:
- Operational analysis
- Regulatory compliance
- Troubleshooting
- Performance optimization
- Business intelligence

It's also valuable for attackers:
- Understanding normal operations (for stealthy attacks)
- Finding patterns and schedules
- Identifying critical setpoints and safety limits
- Discovering network topology and device configurations

Common historian products include:
- OSIsoft PI System (extremely common in process industries)
- GE Proficy Historian  
- Siemens Process Historian
- Wonderware Historian
- Honeywell PHD

Historians often have web interfaces, APIs, and database connections accessible from corporate networks (for business reporting). They're a prime target for attackers seeking to understand industrial operations without directly touching control systems.

### Testing SCADA and historians

SCADA server and historian testing includes:

1. Operating system security: These run on Windows or Linux. Standard OS hardening checks apply. Check patch levels, user accounts, running services, security configurations.

2. Application security: Test the SCADA application itself. Look for default credentials, authentication bypass, authorization flaws, SQL injection in web interfaces, API security issues.

3. Database security: Test historian databases. Check authentication, authorization, encryption, backup security. Many historians use SQL Server, and many use 'sa' account with weak passwords.

4. Web interface testing: Modern SCADA systems provide web-based access. Test these interfaces thoroughly. They often have vulnerabilities because they're developed by industrial automation experts, not web security experts.

5. API security: SCADA systems expose APIs for integration with other systems. Test authentication, authorization, input validation, rate limiting.

At UU P&L, testing the SCADA infrastructure revealed:

The historian web interface had SQL injection vulnerabilities in the trend query page. By crafting malicious queries, you could:
- Extract all data from the historian database
- Retrieve user credentials
- Execute arbitrary SQL commands
- Potentially pivot to other systems via xp_cmdshell

The SCADA server's web interface allowed unauthenticated access to alarm history and real-time values. Whilst it didn't allow sending commands, it provided detailed intelligence about operations.

The historian database used SQL Server with 'sa' account and password "Historian2015" (the year it was installed). This allowed direct database access bypassing application-level security.

The recommendations were extensive and expensive, requiring vendor patches, configuration changes, network segmentation, and rebuilding parts of the infrastructure. The university implemented what they could afford immediately and scheduled the rest for "the next budget cycle" (a phrase that strikes fear into any security consultant's heart).

## Engineering workstations

![PLCs](/_static/images/ot-engineering-workstation.png)

The keys to the kingdom.

Engineering workstations are the computers used to program PLCs, configure SCADA systems, and maintain industrial control systems. They're typically Windows laptops or desktops with vendor-specific engineering software installed.

### Why engineering workstations matter

If you compromise an engineering workstation, you can:
- Program PLCs (upload malicious logic)
- Configure SCADA systems
- Access credentials stored for connecting to industrial devices
- Access project files containing system designs and documentation
- Pivot to control networks (engineering workstations often have access to both corporate and OT networks)

Engineering workstations are the most common entry point for targeted attacks on industrial systems. They're easier to compromise than PLCs, have rich attack surfaces, and provide legitimate access to control systems.

### Common engineering software

- Siemens TIA Portal or STEP 7 (for S7 PLCs)
- Rockwell Studio 5000 or RSLogix (for Allen-Bradley PLCs)
- Schneider Unity Pro or EcoStruxure (for Modicon PLCs)
- SCADA configuration tools (specific to each SCADA platform)
- Various HMI development environments

This software often requires specific versions of Windows, specific .NET Framework versions, and sometimes 32-bit Windows. This leads to engineering workstations running outdated operating systems that can't be upgraded without breaking the engineering software.

### Security characteristics

Engineering workstations are typically:
- Running old Windows versions (XP, 7, even older)
- Not patched (patches might break engineering software)
- Running with administrative privileges (engineering software often requires it)
- Accessible from corporate networks (engineers need to work)
- Used for general purposes (email, web browsing, document editing)
- Shared between multiple engineers (shared accounts are common)
- Connected to multiple networks (corporate, OT, vendor networks)

At UU P&L, the primary engineering workstation is a Windows 7 laptop that:
- Has never been patched (last Windows update in 2016)
- Runs as local Administrator
- Has no antivirus (it was causing "performance issues")
- Connects to both corporate WiFi and OT network
- Contains project files for all PLCs and SCADA systems
- Has vendor VPN clients installed for remote support
- Is used by four different engineers (shared "engineer" account)
- Has passwords written on sticky notes attached to the laptop case

This laptop is effectively the master key to the entire UU P&L infrastructure. Compromise it and you control the 
turbines, reactors, and distribution systems.

### Testing engineering workstations

Engineering workstation testing includes:

1. Operating system security: Check patch levels, security configuration, running services, user accounts. Use tools like [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) or [Watson](https://github.com/rasta-mouse/Watson) to identify missing patches and potential exploits.

2. Application security: Test the engineering software itself. Many vendor tools have vulnerabilities. Check for default passwords, insecure configurations, exposed network services.

3. Credential harvesting: Look for stored credentials in:
   - Project files (often contain PLC passwords)
   - Configuration files
   - Browser password managers
   - Windows credential manager
   - Sticky notes (physical or OneNote)
   - Documentation files

4. Network access analysis: Determine what networks the workstation can reach. It often bridges supposedly segmented networks.

5. USB and removable media: Check what's being used to transfer files. USB drives are common malware vectors in OT.

At UU P&L, examining the engineering workstation (with permission) revealed:

- Project files containing plaintext passwords for all PLCs. 
- SCADA configuration backups with database credentials. 
- Browser history showing the engineer frequently visiting questionable websites (not malicious, just inadvisable on a critical system). 
- Saved RDP sessions to production PLCs with stored credentials. 
- Several USB drives used to transfer files between corporate and OT networks.

The workstation was infected with three different types of malware (adware, not targeted, but still concerning). None 
of the malware had reached the OT network yet, but it was only a matter of time.

The recommendations included:
- Replace the engineering workstation with a properly secured, patched system
- Implement separate workstations for engineering vs general use
- Remove stored credentials from project files
- Implement proper password management
- Restrict network access to only required systems
- Disable USB ports or implement device control
- Deploy endpoint detection and response (EDR) if possible with engineering software

The university's response was to buy a new laptop, install engineering software, and apply some basic hardening. They kept the old laptop "as backup", which means it's still sitting there, still infected, still containing all those credentials, waiting for an incident.

## Safety instrumented systems

The systems you must not break.

Safety Instrumented Systems (SIS) are specialised control systems designed to protect against hazardous events. When 
the normal control system fails or conditions become dangerous, the SIS automatically takes action to bring the 
process to a safe state.

### SIS vs BPCS

The Basic Process Control System (BPCS) is the normal control system (the PLCs and SCADA). It controls the process 
during normal operations.

The SIS is separate and independent. It monitors process conditions and, if danger is detected, takes protective 
action. This might mean:

- Shutting down equipment
- Opening relief valves
- Activating emergency cooling
- Closing isolation valves
- Raising alarms

The key principle is independence. The SIS must work even if the BPCS fails, is compromised, or sends malicious commands.

### SIS architecture

A SIS typically includes:

- Safety PLCs (different from control PLCs, designed for safety applications)
- Safety sensors (reliable, often redundant)
- Final elements (safety valves, emergency shutdown systems)
- Safety HMI (for monitoring, not control)
- Engineering workstation (for configuring safety logic)

Common safety PLC manufacturers:

- Siemens (S7-400FH)
- Rockwell Allen-Bradley (GuardLogix)
- Schneider Electric (Modicon Safety PLCs)
- Triconex/Honeywell
- Yokogawa ProSafe-RS

At UU P&L, the alchemical reactor has a SIS that monitors:

- Reactor temperature (with three independent sensors)
- Pressure (with redundant sensors)
- Containment field strength (magical monitoring)
- Emergency cooling system status

If any parameter exceeds safe limits, the SIS:

- Activates emergency cooling
- Vents pressure to safe release point
- Shuts down the reaction
- Isolates the reactor
- Triggers evacuation alarms

This happens automatically, without human intervention, and without depending on the normal control system.

### Security and safety

Testing SIS requires extreme caution. The safety system protects against hazardous events, including events that 
could injure or kill people. Breaking the safety system during testing could have catastrophic consequences.

IEC 61511 (for process industries) and IEC 61508 (generic functional safety) define requirements for safety systems. 
These standards now include cybersecurity considerations, but implementation varies.

### Testing SIS

When pentesting environments with SIS:

1. Identification: Identify which systems are safety systems. They should be documented, but documentation isn't always accurate.

2. Observation only: For safety systems, limit testing to passive observation and documentation review. Do not send commands, do not attempt to modify logic, do not test write capabilities.

3. Documentation review: Review safety requirements, safety logic, and safety system architecture. Look for cybersecurity gaps without actively testing them.

4. Architecture analysis: Verify that safety systems are truly independent from control systems. Look for inappropriate connections or dependencies.

5. Recommendations without proof: Unlike other systems where you demonstrate vulnerabilities, for safety systems you document theoretical vulnerabilities and recommend mitigations without proving they're exploitable.

At UU P&L, analysis of the reactor SIS revealed:

The safety PLC was properly independent from the control PLC. Good. However, the engineering workstation used to program both systems was the same laptop. Less good. The safety HMI was on the same network as the control SCADA. Problematic. The safety system logged to the same historian as normal operations. Concerning.

These architectural issues meant that whilst the safety system itself was robust, an attacker who compromised the engineering workstation could potentially modify safety logic, and an attacker on the control network could potentially interfere with safety monitoring.

The recommendations focused on improving architectural independence, not testing the safety system's resilience to attack. Because testing by breaking safety systems is a career-limiting move in the "you might go to prison" sense.

## IEDs and the menagerie of intelligent devices

![Windows XP workstation](/_static/images/ot-ieds.png)

Intelligent Electronic Devices (IEDs) is a catch-all term for smart devices in power systems. They include:
- Protective relays (detect faults, trip breakers)
- Power quality meters
- Substation automation controllers
- Phasor measurement units (PMUs)
- Digital fault recorders

These devices are computers running embedded software, with network connectivity, and they perform critical functions in power grid operation.

At UU P&L, the distribution system uses numerous IEDs:
- Protective relays at each substation
- Power quality meters monitoring power factor and harmonics
- Automation controllers for substation control
- PMUs for grid monitoring and stability analysis

### Security characteristics of IEDs

IEDs typically:
- Run embedded operating systems (often Linux, VxWorks, or proprietary RTOS)
- Have web interfaces for configuration
- Support protocols like DNP3, IEC 61850, Modbus
- Have firmware that's rarely updated
- Use default or weak credentials
- Have minimal logging

Testing IEDs is similar to testing other OT devices, but you must be even more careful. Protective relays, for example, are responsible for detecting faults and isolating damaged equipment. Breaking a relay during testing could leave equipment unprotected.

## The forgotten Windows XP box in the corner

![Windows XP workstation](/_static/images/ot-windowsxp-workstation.png)

In almost every OT environment, there's a computer sitting in a corner, covered in dust, with yellowing plastic and a CRT monitor (or at least a very old LCD). Nobody's quite sure what it does. Nobody dares turn it off. It's been running continuously since it was installed in 2004.

This computer is often:
- Running Windows XP or older
- Never patched
- Connected to the network (because it needs to be, apparently)
- Running critical software that nobody has installation media for anymore
- Accessible with no password or an obvious password
- Not documented in any asset inventory

At UU P&L, there's a Windows 98 machine in the turbine hall running data collection software from the original 
turbine vendor. It polls turbine data via serial connection, logs it to local CSV files, and makes the data available 
via a network share.

This machine has been running since 1998. It cannot be upgraded because the data collection software won't run on 
newer Windows. It cannot be retired because maintenance contracts require this specific data format. It cannot be 
secured because applying security policies breaks the software.

It sits there, a monument to technical debt, accessible via SMBv1 with no password, containing 25 years of turbine 
operational data, and serving as a potential pivot point into the turbine control network.

### Testing forgotten systems

These systems are goldmines for pentesters:
- Ancient operating systems with countless vulnerabilities
- No security updates possible
- Often connected to critical systems
- Rarely monitored
- Administrators often don't remember they exist

The recommendations for these systems usually are:
- Isolate them on separate network segments
- Implement strict firewall rules (only required connections)
- Monitor all access
- Consider virtualising them if possible
- Document them properly (so they're not forgotten again)
- Plan for eventual replacement (though this rarely happens)

At UU P&L, the recommendation was to isolate the Windows 98 machine on its own VLAN, implement firewall rules 
allowing only necessary connections, and monitor all access attempts. The university implemented the firewall rules 
(relatively easy) and added it to the asset inventory (free). The monitoring was "under consideration" (meaning 
probably never).
