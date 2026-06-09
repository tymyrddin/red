# HMI security: Interface between operators and reality

![HMI](/_static/images/ot-hmi.png)

*Or: Why Ponder Focused on Protocols Rather Than Pixels*

## The operator's view

Human-Machine Interfaces are where operators interact with industrial processes. They're the screens showing graphics of turbines spinning, tanks filling, and valves opening. They're the buttons that make things happen in the physical world. At UU Power & Light, operators spent 12-hour shifts staring at the FUXA HMI displays, monitoring hundreds of data points and occasionally clicking buttons to acknowledge alarms or adjust setpoints.

The lab includes the control HMI (`uupl-hmi`), running FUXA 1.1.7. Ponder noted its presence but didn't focus his testing on the screens themselves at first. This wasn't an oversight. This was a deliberate choice about where the unique security challenges in OT actually existed.

## Why HMIs are different (and also not)

HMIs are typically Windows-based applications running on general-purpose computers. This meant they inherited all the security problems of Windows, plus application-specific vulnerabilities, plus configuration mistakes made during deployment. Unlike PLCs which have limited attack surfaces, HMIs are full-featured computers with web browsers, file systems, user accounts, and network connectivity.

In other words, HMI security is largely IT security. The vulnerabilities are familiar:
- Default credentials (admin/admin, operator/operator)
- SQL injection in alarm search functions
- Path traversal in file download features
- Command injection in diagnostic tools
- Session management flaws
- Authentication bypass vulnerabilities

These are all real vulnerabilities found in real industrial HMIs. They're serious, they're common, and they're well-documented in standard IT security literature. The testing methodology is standard web application security assessment, just applied to industrial interfaces.

## What makes OT security different

What Ponder focused on in his testing wasn't the HMI applications themselves. It was what came after: the industrial protocols that HMIs use to communicate with PLCs and SCADA systems.

The attack path involving HMIs typically looks like:
1. Compromise a workstation on the corporate network (phishing, vulnerability, etc.)
2. Pivot to an HMI system (same Windows domain, shared credentials, etc.)
3. Use the HMI to access industrial protocols (HMIs legitimately connect to PLCs/SCADA)
4. Attack industrial systems through those legitimate connections

Steps 1-3 are IT security. Standard penetration testing, lateral movement, credential theft. There are excellent resources covering these topics.

Step 4 is where OT security becomes its own discipline. Once you have access to speak Modbus, IEC-104, or OPC UA, what do you do? How do you read a PLC's registers? How do you enumerate OPC UA tags and call its methods? How do you falsify a datapoint? How do you modify setpoints without triggering alarms?

That's what the simulator teaches.

## The simulator's deliberate focus

The UU P&L simulator includes HMI workstations in its architecture, but doesn't implement HMI application vulnerability testing. Instead, it assumes the attacker has already compromised an HMI (or gained network access through some other means) and focuses on what comes next:

What the simulator teaches:
- How industrial protocols actually work
- What authentication (or lack thereof) looks like in OT
- How to enumerate and map industrial devices using protocol-specific commands
- What information disclosure means in control systems
- How to extract PLC programmes and SCADA configurations
- How protocol-level attacks differ from IT attacks

What standard IT security resources cover:
- How to exploit web application vulnerabilities
- How to crack Windows passwords
- How to perform SQL injection
- How to bypass authentication in web interfaces
- How to pivot through networks

## HMIs as the bridge

HMIs are dangerous in OT environments not because they're technically sophisticated targets. They're dangerous because they bridge IT and OT networks, and that bridge is often poorly defended on both sides.

The simulator's architecture includes this bridge:
- The control HMI `uupl-hmi` (FUXA 1.1.7)
- The engineering workstation `uupl-eng-ws` (dual-homed into control)
- The enterprise workstation `bursar-desk` (over-privileged, the phishing target)

These workstations exist in the configuration, representing the various entry points an attacker might use. But the simulator's testing focus is on what happens after compromise: the protocol-level interactions with PLCs and SCADA systems.

## What Ponder's testing revealed

Ponder's testing journal acknowledged the HMIs but explained why protocol testing mattered more:

"HMI compromise is often straightforward. They're Windows boxes with web interfaces, database backends, and all the familiar vulnerabilities. Standard web application security testing finds the problems, standard exploitation techniques gain access.

"But once you're in, then what? The HMI has legitimate connections to the PLC over Modbus, DNP3, and IEC-104. It connects to the SCADA server, and the OPC UA endpoints sit alongside. It has engineering reach into the field devices.

"Knowing how to exploit a web application gets you to the HMI. Knowing how to enumerate Modbus registers, falsify an IEC-104 datapoint, and browse and call OPC UA methods... that's what lets you actually affect the industrial process.

"That's the difficult part. That's what's uniquely OT. That's what the simulator teaches."

## The realistic threat model

In actual OT security assessments, HMI compromise is often trivial. They run outdated software, have default credentials, lack proper segmentation from corporate networks, and inherit decades of Windows vulnerabilities. Getting access to an HMI is usually not the challenge.

The challenge is knowing what to do with that access. The simulator assumes you've already solved the HMI compromise problem (either through actual exploitation or by being given access for authorised testing) and teaches the next step: interacting with industrial protocols safely, effectively, and with understanding.

## Where the protocols meet the interface

The HMIs in the simulator architecture represent the endpoint from which an attacker would launch protocol-level attacks. They're the system that legitimately connects to:
- The turbine PLC via Modbus TCP (port 502)
- The turbine PLC over DNP3 and IEC-104
- The OPC UA endpoints (the turbine sidecar and the DMZ gateways) on port 4840
- The protective relays and actuators via Modbus

The simulator's testing scripts demonstrate what an attacker would do from a compromised HMI: enumerate devices, read configurations, extract programmes, and understand the industrial process through protocol-level reconnaissance.

This is where HMI security meets protocol security. The HMI is the tool through which attacks are launched, but the protocols are where the actual industrial system compromise occurs.

## Scripts run from the HMI perspective

Whilst the simulator doesn't include HMI application vulnerability testing, all the reconnaissance and vulnerability 
assessment scripts represent what an attacker would do from a compromised HMI or engineering workstation.

Reconnaissance from an HMI:
- Raw TCP probing - Initial connectivity testing
- Turbine reconnaissance - Comprehensive Modbus enumeration
- Modbus identity probe - Device fingerprinting
- OPC UA connection test - SCADA connectivity

Vulnerability assessment from an HMI:
- Modbus snapshot: read all registers and coils
- OPC UA probe: anonymous browsing and method calls
- IEC-104 interrogation: datapoint enumeration
- Relay threshold read: the protection limits in the holding registers

All of these scripts assume you're running them from a system that has network access to the OT protocols. In a real 
assessment, that system would typically be a compromised HMI or engineering workstation.

The HMI is the launching point. The scripts demonstrate what happens after launch.

## The educational value

Standard IT security training teaches how to compromise HMIs. The UU P&L simulator teaches what to do next.

It's the difference between knowing how to pick a lock (IT security) and knowing what to do once you're inside the building (OT security). Both are necessary. One is well-covered by existing training. The other requires understanding industrial protocols, PLC architectures, and SCADA configurations.

Ponder's conclusion: "HMI security is important. It's also mostly IT security with industrial consequences. Protocol security is what makes OT genuinely different, and it's what most security professionals don't understand.

"The simulator teaches the different part."

Further reading:

- [PLC Security Testing](plc.md) - Protocol-level vulnerabilities in controllers
- [SCADA Security Testing](scada.md) - OPC UA and supervisory systems
- [Network Security](network.md) - Reconnaissance and protocol fingerprinting
- [Workstation Security](workstation.md) - Engineering access and entry points

For HMI application security testing, standard web application security resources apply. The simulator focuses on 
industrial protocol security, assuming access to the OT network has already been achieved through HMI compromise or 
other means.
