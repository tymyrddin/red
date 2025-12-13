# Threat modelling for OT

Before you start testing an OT environment, you need to think like an attacker. Not just any attacker, but the specific types of attackers who might target industrial control systems, each with different motivations, capabilities, and methods.

Threat modelling helps you:
- Focus testing efforts on realistic attack scenarios
- Prioritize findings based on actual threat likelihood
- Communicate risks in terms business stakeholders understand
- Avoid wasting time on theoretical vulnerabilities that no real attacker would exploit

The challenge in OT is that threats are different from IT. Web applications worry about credit card theft. Industrial control systems worry about physical sabotage, safety incidents, and operational disruption.

Who might attack Unseen University Power & Light Co., why they'd do it, and how they'd go about it?

## Asset identification and criticality

Not everything is equally critical. The turbines generating power for half of Ankh-Morpork are somewhat more 
important than the coffee machine in the break room (though operators might dispute this). At UU P&L, critical assets 
include:

### Primary power generation
- Hex Steam Turbines (three units, 50 MW each)
- Boiler control systems
- Turbine control PLCs
- Governor systems (control turbine speed)
- Protection systems (prevent turbine damage)

Loss of these systems means city-wide power outage, significant financial losses, and an extremely unhappy Patrician.

### Secondary but still critical
- Alchemical reactor (experimental power source)
- City distribution SCADA (manages power distribution)
- Substation RTUs (enable remote control of grid)

Loss means cascading failures, inability to manage the grid, and potential equipment damage.

### Important but not immediately critical
- Library environmental system (temperature/humidity control)
- Building automation (HVAC, lighting)
- Administrative systems (billing, reporting)

Loss causes problems but not immediate danger. Though an overheated Library leading to an angry Librarian could be argued as a safety concern.

### Categorising by consequence

For each asset, consider consequences of compromise:

Safety: Could compromise cause injury or death?
- Turbine control: Yes (mechanical failure, steam explosion)
- Reactor control: Very yes (containment failure, alchemical incident)
- Safety systems: Yes (by definition, they prevent injuries)
- HVAC: No (discomfort, but not danger)

Environmental: Could compromise cause environmental damage?
- Reactor: Yes (magical contamination, chemical release)
- Turbines: Possibly (steam releases, fuel spills)
- Distribution: No direct environmental impact

Financial: What would compromise cost?
- Power outage: Millions per hour in lost revenue and compensation
- Equipment damage: Turbines cost £15 million each
- Regulatory fines: Varies, but substantial

Reputational: How would compromise affect trust?
- Major incident: Loss of public confidence, regulatory intervention
- Minor incident: Embarrassment, scrutiny
- No incident but vulnerability disclosed: Damage to professional reputation

Operational: How long to recover?
- Simple configuration change: Hours
- Equipment damage: Weeks to months
- Loss of control system: Days to weeks
- Safety system failure: Cannot operate until fixed

This categorisation helps prioritize protection efforts and testing focus. You spend more time on turbine controls (high consequence across all categories) than on building HVAC (low consequence).

## Threat actors, who wants to attack a power plant

Different attackers have different capabilities and motivations. Understanding who might target you helps determine what attacks to defend against.

### Nation state actors

Motivation: Strategic advantage, intelligence gathering, pre-positioning for future conflict, coercion, retaliation.

Capabilities: 
- Sophisticated malware development
- Zero-day exploits
- Long-term persistent access
- Social engineering and insider recruitment
- Supply chain compromise
- Significant resources and patience

Targets at UU P&L:
- Turbine controls (disrupt power to the city)
- Distribution SCADA (create cascading failures)
- Safety systems (cause incidents)
- Engineering workstations (establish persistence)

Attack methods:
- Spear phishing engineers and operators
- Watering hole attacks on industry websites
- Supply chain compromise of vendor software
- Physical infiltration (installing implants)
- Insider threats (recruitment or coercion)

Likelihood for UU P&L: Low to medium. Ankh-Morpork isn't a major geopolitical player, but it's strategically located. A nation state wanting to destabilise the region might consider UU P&L a viable target.

### Ransomware gangs

Motivation: Money, purely money, nothing but money.

Capabilities:
- Commodity malware and exploits
- Social engineering
- Some custom tool development
- Purchasing zero-days on criminal markets
- Effective encryption and communication security
- Negotiation and payment infrastructure

Targets at UU P&L:
- Any system they can encrypt
- Backups (to prevent recovery without paying)
- File servers and databases
- Less interest in operational disruption than data encryption

Attack methods:
- Phishing emails to corporate users
- RDP brute forcing
- Exploiting known vulnerabilities in perimeter systems
- Purchasing initial access from access brokers
- Lateral movement to maximize encryption impact

Likelihood for UU P&L: High. Ransomware is indiscriminate. Any organisation with money is a target. UU P&L, as critical infrastructure, is attractive because they're more likely to pay.

The university did experience a ransomware incident in 2019. It hit corporate IT, encrypted file servers and workstations. Thankfully it didn't reach OT networks (the poor network connectivity between IT and OT finally paid off). The university paid 50 bitcoin. They never disclosed this publicly because "it would undermine confidence in university security" (translation: it's embarrassing).

### Hacktivists

Motivation: Ideology, publicity, revenge, "sending a message", chaos for chaos's sake.

Capabilities:
- Variable, from script kiddies to sophisticated
- DDoS attacks
- Website defacement
- Data leaks
- Basic exploitation of known vulnerabilities
- Social engineering
- Insider access (sympathetic employees)

Targets at UU P&L:
- Public-facing websites
- Systems for maximum disruption/publicity
- Data for leaking to embarrass the university
- Less interest in subtle attacks, more in dramatic visible impacts

Attack methods:
- Website defacement
- DDoS attacks on public services
- Social engineering to gain access
- Data theft and publication
- Disruption attacks on visible infrastructure

Likelihood for UU P&L: Medium. Universities attract protest. If UU P&L does something unpopular (like raising electricity prices, or a controversial policy), hacktivists might target them. Most likely outcome is website defacement or DDoS, but more capable groups might attempt more serious disruption.

### Disgruntled insiders

Motivation: Revenge (termination, discipline, perceived injustice), financial gain, ideology.

Capabilities:
- Legitimate access to systems
- Knowledge of security controls and how to evade them
- Understanding of what will cause most damage
- Trust from colleagues (social engineering)
- Physical access to facilities

Targets at UU P&L:
- Systems they have access to
- Systems that will cause maximum disruption
- Data for theft or destruction
- Safety systems (if truly malicious)

Attack methods:
- Using legitimate credentials to perform malicious actions
- Planting logic bombs (trigger after they leave)
- Sabotaging equipment or configurations
- Stealing credentials for later use
- Data exfiltration
- Physical sabotage

Likelihood for UU P&L: Medium. Employee terminations happen. Disciplinary actions happen. People hold grudges. The university has had incidents of minor sabotage (nothing involving control systems, mostly "accidentally" breaking things or withholding knowledge during handover).

The risk is particularly high because:
- Many systems have shared accounts (hard to attribute actions)
- Logging is minimal (hard to detect malicious activity)
- Insider knowledge makes attacks more effective
- Cultural trust means suspicious activity might not be reported

### Incompetent contractors

Motivation: None. They're not attacking, they're just catastrophically incompetent.

Capabilities:
- Legitimate access
- Dangerous combination of partial knowledge and overconfidence
- Ability to cause harm through negligence

Targets at UU P&L:
- Anything they're working on
- Anything adjacent to what they're working on
- Anything that breaks when they do something they shouldn't

Attack methods (unintentional):
- Misconfigurations during maintenance
- Accidentally deleting configurations
- Installing malware via infected USB drives
- Bridging networks that should be separate
- Disabling security controls "to make things work"
- Using default credentials and never changing them
- Leaving backdoors for convenience

Likelihood for UU P&L: High. This happens constantly. It's not malicious, but the impact can be equivalent to an attack.

Examples from UU P&L history:
- Contractor installed wireless access point, bridged IT and OT networks
- Contractor disabled antivirus on SCADA server "because it was causing CPU usage"
- Contractor uploaded wrong program to PLC, caused three-hour outage
- Contractor left remote access VPN credentials in documentation, credentials never changed
- Contractor's laptop infected with malware, spread to engineering workstation

### Script kiddies and opportunistic attackers

Motivation: Curiosity, boredom, bragging rights, minor financial gain.

Capabilities:
- Use of readily available tools
- Exploiting known vulnerabilities
- Following tutorials
- Limited understanding of what they're doing
- Unlikely to develop custom tools

Targets at UU P&L:
- Anything exposed to internet
- Anything found via Shodan or similar scanning
- Low-hanging fruit with known vulnerabilities

Attack methods:
- Scanning for open ports and known vulnerabilities
- Using Metasploit modules
- SQL injection via automated tools
- Credential stuffing
- Exploiting default passwords

Likelihood for UU P&L: Medium for attempt, low for success. These attackers are noisy, easily detected, and usually stopped by basic security. However, if UU P&L has internet-exposed OT systems (which they do, via vendor remote access), these attackers might stumble in accidentally.

## Attack vectors and kill chains for OT

Understanding how attackers might penetrate and move through your environment helps focus defensive and testing efforts.

### The ICS Cyber Kill Chain

The traditional cyber kill chain (reconnaissance, weaponisation, delivery, exploitation, installation, command and control, actions on objectives) applies to OT, but there's an OT-specific variation that better captures the stages of industrial system attacks:

Stage 1: Reconnaissance

Attackers gather information about the target:
- Open source intelligence (OSINT) gathering
- Network scanning (externally if exposed, internally after initial compromise)
- Identifying OT assets, protocols, and vendors
- Social engineering for information
- Physical reconnaissance of facilities

At UU P&L, reconnaissance might reveal:
- Public job postings mentioning specific SCADA software
- Vendor announcements about projects at the university
- LinkedIn profiles of engineers listing skills and tools
- Shodan results showing exposed HMI web interfaces
- University publications describing the alchemical reactor
- Physical observation of facilities and security measures

Stage 2: Initial intrusion

Getting first access to the target environment:
- Phishing emails to corporate users
- Exploiting perimeter vulnerabilities
- Compromising vendor remote access
- Physical intrusion
- Insider access

For UU P&L, most likely vectors:
- Phishing targeting engineers (successful 30% of the time based on tests)
- Exploiting vulnerabilities in corporate IT perimeter
- Compromising vendor VPN (using leaked credentials or exploits)
- USB malware introduced via contractor laptops
- Wireless access via that convenient access point in the turbine hall

Stage 3: Establish presence

Once inside corporate IT, establish persistent access:
- Installing backdoors
- Creating rogue accounts
- Stealing credentials
- Deploying remote access tools
- Avoiding detection

Stage 4: Move to OT

Pivot from corporate IT to OT networks:
- Exploiting trust relationships
- Using compromised jump hosts
- Leveraging engineering workstations that bridge networks
- Exploiting poor network segmentation
- Using legitimate remote access paths

At UU P&L, this is easier than it should be:
- Jump host accessible from corporate IT with shared credentials
- Engineering workstation bridges both networks
- That wireless access point bridges IT and OT
- Historian on corporate network can query SCADA server
- No monitoring at IT/OT boundary

Stage 5: Discovery and reconnaissance

Map the OT environment:
- Passive network monitoring
- Active scanning (carefully)
- Querying PLCs and SCADA systems
- Analyzing network traffic
- Stealing project files and documentation

Stage 6: Development

Prepare attack tools and payloads:
- Analyzing control logic from stolen PLC programs
- Developing custom malware
- Testing attacks in lab environment
- Planning attack timing and triggers

Nation state actors might spend months in this phase. Ransomware gangs skip it entirely.

Stage 7: Impact

Execute the attack:
- Modifying PLC logic
- Sending malicious commands
- Disrupting safety systems
- Encrypting systems (ransomware)
- Destroying data or configurations
- Physical damage to equipment

For UU P&L scenarios:
- Modifying turbine control logic to cause mechanical damage
- Disabling safety systems then causing dangerous conditions
- Encrypting SCADA servers and engineering workstations
- Manipulating distribution controls to cause grid instability
- Altering reactor setpoints to cause containment issues

## STRIDE for industrial systems

STRIDE is a threat modelling framework originally developed by Microsoft. It categorises threats into six types: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

Applied to OT environments at UU P&L:

### Spoofing (pretending to be something or someone else)

*IT examples*:
- Using stolen credentials to log into SCADA HMI
- Spoofing IP addresses to impersonate legitimate devices
- Replaying captured authentication credentials

*OT-specific examples*:
- Sending Modbus commands with spoofed source address
- Injecting DNP3 messages pretending to be from the master station
- Pretending to be a legitimate engineering workstation when programming PLCs

*UU P&L scenarios*:
- Attacker spoofs engineer workstation IP, uploads modified logic to turbine PLC
- Attacker captures and replays DNP3 commands to RTUs, operating breakers
- Attacker uses stolen HMI credentials, sends commands that appear legitimate

*Mitigations*:
- Authentication at protocol level (where supported)
- Network segmentation (reducing ability to spoof)
- Monitoring for unusual command sources
- Certificate-based device authentication

### Tampering (modifying data or code)

*IT examples*:
- Modifying database records
- Changing configuration files
- Altering log files to hide tracks

*OT-specific examples*:
- Modifying PLC ladder logic
- Changing SCADA setpoints or alarm limits
- Tampering with sensor readings
- Altering historian data

*UU P&L scenarios*:
- Attacker modifies reactor PLC logic to disable high-temperature shutdown
- Attacker changes turbine alarm limits so dangerous conditions don't trigger alerts
- Attacker modifies historian data to hide evidence of manipulation
- Attacker tampers with sensor readings to mislead operators

*Mitigations*:
- Code signing for PLC programs (where supported)
- Change detection and monitoring
- Integrity checking of configurations
- Separate logging systems attackers can't access
- Physical key switches preventing unauthorized program changes

### Repudiation (denying responsibility for actions)

*IT examples*:
- Performing actions without logging
- Deleting or disabling logs
- Using shared accounts (no attribution)

*OT-specific examples*:
- Sending PLC commands with no audit trail
- Using shared engineering credentials (can't prove who did what)
- Modifying configurations without triggering logged events
- Disabling logging on HMIs and SCADA

*UU P&L scenarios*:
- Multiple engineers use shared "engineer" account, impossible to determine who made catastrophic configuration change
- Attacker accesses PLC via Modbus, leaves no log of commands sent
- Insider performs malicious actions, claims system malfunctioned
- Attacker disables SCADA audit logs before performing attack

*Mitigations*:
- Individual user accounts (eliminate shared credentials)
- Comprehensive logging at network and application level
- Tamper-proof logging (logs sent to separate system)
- Time synchronization (accurate timestamps)
- Video monitoring of control rooms and critical areas

### Information Disclosure (exposing information to unauthorised parties)

*IT examples*:
- Stealing customer data
- Exfiltrating intellectual property
- Reading confidential communications

*OT-specific examples*:
- Stealing PLC programs (intellectual property and attack intelligence)
- Exfiltrating process data (competitive intelligence)
- Capturing network traffic (understanding operations)
- Stealing engineering documentation

*UU P&L scenarios*:
- Attacker downloads all PLC programs, learns control strategies and vulnerabilities
- Competitor steals alchemical reactor designs and operational data
- Nation state exfiltrates grid operations data for future attacks
- Ransomware gang steals data before encryption for double extortion

*Mitigations*:
- Access controls on project files and documentation
- Encryption of sensitive data at rest and in transit
- Network segmentation preventing data exfiltration paths
- Data loss prevention monitoring
- Classification and protection of critical information

### Denial of Service (making systems unavailable)

*IT examples*:
- DDoS attacks on web servers
- Resource exhaustion attacks
- Crashing applications

*OT-specific examples*:
- Flooding industrial networks with traffic
- Crashing PLCs with malformed packets
- Encrypting SCADA servers (ransomware)
- Disabling safety systems

*UU P&L scenarios*:
- Attacker floods turbine control network, PLCs miss sensor readings, turbines trip
- Attacker sends malformed S7comm packets, reactor PLC crashes, reactor shuts down
- Ransomware encrypts SCADA servers, operators lose visibility and control
- Attacker manipulates process to trigger safety shutdowns repeatedly

*Mitigations*:
- Rate limiting at network level
- Robust protocol parsing in devices
- Redundant systems
- Backup control capabilities
- Anomaly detection for unusual traffic patterns
- Offline backups and recovery procedures

### Elevation of Privilege (gaining higher levels of access)

*IT examples*:
- Exploiting vulnerabilities to gain admin rights
- Stealing privileged credentials
- Exploiting misconfiguration

*OT-specific examples*:
- Compromising engineering workstation to gain PLC programming ability
- Escalating from HMI operator access to administrator
- Exploiting SCADA vulnerabilities to execute arbitrary commands
- Moving from corporate IT to OT networks

*UU P&L scenarios*:
- Attacker compromises operator HMI account, exploits vulnerability to gain administrator rights
- Attacker pivots from corporate IT to engineering workstation to PLC access
- Attacker exploits SCADA web interface vulnerability, executes commands as SYSTEM
- Contractor laptop compromised, used to access control networks

*Mitigations*:
- Principle of least privilege
- Network segmentation between trust zones
- Patching known vulnerabilities
- Application whitelisting
- Removing unnecessary privileges from applications
- Monitoring for privilege escalation attempts

## Safety vs security trade-offs

One of the unique challenges in OT threat modelling is the tension between safety and security. Sometimes these goals conflict.

### Safety prioritises availability and predictability

Safety systems need to:
- Always be available when needed
- Respond predictably to dangerous conditions
- Be simple and reliable
- Failsafe (default to safe state)
- Be testable and verifiable

This often means:
- Redundant systems (more attack surface)
- Simple designs (less security sophistication)
- Avoiding complexity (including security complexity)
- Preferring availability over confidentiality

### Security prioritises controlled access and integrity

Security systems need to:
- Restrict access to authorised users
- Verify authenticity of commands
- Detect and prevent unauthorized modifications
- Log all actions for audit
- Isolate systems to prevent compromise spread

This often means:
- Authentication and authorization (complexity, potential failure points)
- Encryption (performance impact, key management complexity)
- Monitoring and alerting (additional systems and networks)
- Restricting access (potential availability impact)

### When they conflict

At UU P&L, examples of safety/security conflicts:

The reactor safety system

Safety requirement: Must shut down reactor if any safety parameter is exceeded, regardless of any other factors. Must work even if all other systems fail.

Security requirement: Should verify commands are authentic, should not accept shutdown commands from unauthorized sources.

Conflict: Adding authentication to safety shutdown creates a potential failure point. If authentication fails or has a bug, it might prevent legitimate safety shutdowns. Safety requirements say "when in doubt, shut down". Security requirements say "when in doubt, deny access".

Resolution: Safety takes priority. The safety system must work even if security is compromised. Security controls are implemented at network level (preventing unauthorized access to safety system network), not at protocol level (which might interfere with safety function).

The remote access dilemma

Safety requirement: Vendor must be able to access systems quickly during emergency to provide troubleshooting support. Four-hour response time contractually mandated.

Security requirement: Remote access should be tightly controlled, require approval, use strong authentication, be monitored, and ideally not exist at all.

Conflict: Strict security controls on remote access slow down vendor response. In an emergency where turbines are behaving erratically, waiting for security approval process might delay critical support.

Resolution: Compromise. Vendor has remote access but it's monitored, logged, requires two-factor authentication, and uses VPN with strong encryption. University retains right to disable access if compromise suspected. Not perfect from security perspective (persistent remote access is risky), not perfect from safety perspective (still some authentication overhead), but acceptable balance.

The patching problem

Safety requirement: Control systems must be stable and unchanging. Patches might introduce instability or bugs that affect safety-critical functions.

Security requirement: Systems must be patched to address vulnerabilities.

Conflict: Patching requires downtime, testing, and risk of introducing problems. Not patching leaves vulnerabilities exploitable.

Resolution: Risk-based approach. Critical security patches tested extensively in non-production environments before deployment. Less critical patches deferred or mitigated via compensating controls. Some systems never patched because risk of patch causing problems exceeds risk of vulnerability.

The key principle: Safety cannot be compromised for security. If security controls might interfere with safety functions, safety wins. But this doesn't mean ignoring security; it means finding security controls that don't interfere with safety.

## Crown jewels and acceptable losses

Not everything needs equal protection. Some systems are so critical that their compromise is unacceptable. Others are important but their loss is survivable.

### Crown jewels at UU P&L

Systems whose compromise is absolutely unacceptable:

1. Turbine safety systems: If compromised, could cause physical damage to turbines, steam explosions, or injuries. Loss of 50MW turbines would cost millions to replace, cause city-wide outages, and potentially injure personnel.

2. Reactor safety systems: If compromised, could cause containment failure, alchemical incident, or explosion. Consequences range from "evacuation of campus" to "evacuating half of Ankh-Morpork".

3. Distribution SCADA master: If compromised, attacker could manipulate entire city grid, causing cascading blackouts, equipment damage across the system, and inability to restore power quickly.

These systems get maximum security investment, most restrictive access controls, and most intensive monitoring.

### Important but not crown jewels

Systems whose compromise is very bad but survivable:

1. Turbine control systems (non-safety): If compromised, can cause turbine trips and outages, but safety systems prevent physical damage. Significant financial impact and inconvenience, but not catastrophic.

2. HMIs and operator stations: If compromised, lose visibility and control, but can operate manually or from backup stations. Degraded operations but not complete loss.

3. Historian: If compromised, lose operational data and business intelligence, but doesn't directly affect physical processes. Data loss is bad, but not an immediate safety concern.

These systems get good security, but trade-offs are acceptable when they conflict with operational needs.

### Acceptable losses

Systems whose compromise is annoying but not catastrophic:

1. Corporate IT systems: If compromised, causes business disruption but doesn't affect power generation or distribution directly.

2. Building HVAC: If compromised, causes discomfort but not danger (except possibly the Library).

3. Ancillary systems: Security cameras, door access, cafeteria systems. Their loss doesn't affect core mission.

These systems get basic security but don't warrant significant investment if resources are limited.

This prioritisation helps allocate security resources effectively. You spend more effort protecting crown jewels than protecting the corporate email system. You accept some risk to ancillary systems to focus resources on critical infrastructure.

It also helps during incident response. If under attack, you focus first on protecting crown jewels. If forced to choose between protecting the SCADA system and protecting corporate file servers, the choice is obvious.

Threat modelling isn't just an academic exercise. It shapes how you test, what you test, what vulnerabilities matter most, and what recommendations you prioritize. Without understanding threats, you're just finding vulnerabilities without context. With good threat modelling, you're providing actionable security intelligence that helps protect what actually matters.

And at UU P&L, what actually matters is keeping the power on, the reactor contained, and the Librarian comfortable. Everything else is negotiable.