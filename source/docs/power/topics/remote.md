# Wireless and remote access: When the air gap has bridges

*Or: Why Ponder Didn't Test What Wasn't There (But Should Have Been)*

## The problem with air gaps

The term "air gap" in OT security refers to the theoretical isolation of control systems from external networks through the simple expedient of not connecting them to anything. It's a wonderfully simple security model: if there's no physical connection, there can be no network intrusion. This works brilliantly right up until someone needs to access the system remotely, at which point the air gap acquires a bridge, and then another bridge for redundancy, and before long you have more bridges across your air gap than the River Ankh has crossing points.

The Ankh is famously more solid than liquid, to the point where you can almost walk across it if you're brave and have had your tetanus shots. The air gaps in most OT environments have achieved a similar state of solidity. They're still called air gaps, everyone agrees they exist, but in practice they're permeated with wireless access points, 4G routers, Bluetooth devices, satellite links, and various other forms of electromagnetic radiation that rather undermine the whole "air" aspect of the gap.

At actual facilities (the sort Ponder visited during consulting work), the official network architecture showed pristine air gaps between control networks and everything else. The reality, discovered during wireless surveys, was that control networks had more wireless access points than corporate networks, including multiple 4G routers, satellite modems, collections of Bluetooth-enabled sensors, Zigbee networks for building automation that somehow intersected with industrial controls, and enthusiastic contractors who'd installed their own solutions.

## What the simulator doesn't test (yet)

The UU P&L simulator currently runs entirely on localhost (127.0.0.1). There are no wireless protocols, no remote access mechanisms, no vendor VPNs, no 4G modems hidden in junction boxes. Everything communicates over local TCP/IP on specific ports.

This is a deliberate simplification. The simulator focuses on industrial protocol vulnerabilities, not wireless security or remote access security. Those are important topics, but they're largely covered by existing IT security resources and tools.

Current simulator scope:
- Industrial protocols: Modbus, S7, OPC UA, EtherNet/IP
- PLC vulnerabilities: Unauthenticated access, memory reading, logic extraction
- SCADA vulnerabilities: Anonymous OPC UA access, tag enumeration
- Network reconnaissance: Protocol fingerprinting, device discovery

Not currently in simulator scope:
- Wireless networks: WiFi, Bluetooth, Zigbee, LoRa
- Remote access: VPNs, cellular modems, satellite links
- Vendor access: Remote desktop, jump hosts, privileged access management
- Physical security: Rogue access points, unauthorised modems

This doesn't mean these topics aren't important. It means they're outside the current simulator's focus on industrial protocol security.

## Why wireless and remote access matter in OT

Wireless and remote access represent significant attack vectors in real OT environments:

### Rogue access points

Contractors install unauthorised wireless networks because they need network access during maintenance and the official process takes too long. These rogue access points:
- Bypass network security controls
- Provide unmonitored access to control networks
- Often use weak or default passwords
- Remain active long after contractors leave

### Cellular modems

Vendors install 4G modems for remote monitoring and troubleshooting. These create direct internet connections that:
- Bypass firewalls and network segmentation
- Provide permanent vendor access
- Often use default credentials
- May be unknown to facility operators

### Bluetooth sensors

Industrial IoT devices increasingly use Bluetooth for wireless sensor connectivity. These often:
- Use no encryption
- Have no authentication
- Accept connections from any device within range
- Transmit sensitive process data

### Vendor VPNs

Equipment vendors require remote access for support and maintenance. These VPN connections:
- Provide direct access to control systems
- Are often always-on rather than scheduled
- May have excessive privileges
- Depend on vendor network security

Each of these represents a bridge across the supposed air gap, and each represents an attack vector that protocol-level security cannot address.

## What could be added to the simulator

Future simulator enhancements could include:

### Wireless protocol simulation

Rogue access point testing:
- Simulated WiFi networks with weak security
- Scripts to identify rogue APs by MAC address patterns
- Tools to demonstrate WPA2-PSK cracking against weak passwords
- Educational content on wireless security best practises

Bluetooth security testing:
- Simulated Bluetooth sensors transmitting process data
- Scripts to enumerate Bluetooth devices
- Demonstrations of unencrypted Bluetooth data capture
- Tools to show authentication bypass vulnerabilities

Why this would be valuable:
- Demonstrates that protocol security alone isn't sufficient
- Shows how wireless bridges undermine network segmentation
- Teaches wireless security assessment techniques
- Illustrates real-world attack paths into control systems

### Remote access simulation

Vendor VPN scenarios:
- Simulated vendor VPN with always-on access
- Scripts to demonstrate lateral movement from vendor network
- Tools to show excessive privilege exploitation
- Educational content on vendor access management

Cellular modem discovery:
- Simulated cellular gateway providing internet access
- Scripts to identify unauthorised remote access devices
- Tools to demonstrate default credential exploitation
- Guidance on detecting hidden remote access

Why this would be valuable:
- Shows how vendor access bypasses security controls
- Demonstrates supply chain security risks
- Teaches remote access security assessment
- Illustrates real-world compromise scenarios

### Physical security integration

Unauthorised device detection:
- Simulated network with hidden access points
- Scripts to discover devices not in asset inventory
- Tools to identify suspicious network behaviour
- Educational content on physical security assessment

Why this would be valuable:
- Connects physical and cyber security
- Shows importance of asset inventory
- Demonstrates that security must consider physical access
- Teaches comprehensive security assessment methodology

## The relationship to protocol security

Wireless and remote access vulnerabilities matter because they provide the initial access that enables protocol-level attacks.

Typical attack progression:

1. Initial access via wireless or remote access vulnerability
   - Compromise rogue WiFi network with weak password
   - Exploit vendor VPN with default credentials
   - Connect via discovered cellular modem

2. Network reconnaissance using industrial protocol tools
   - Port scanning to discover PLCs and SCADA servers
   - Protocol fingerprinting to identify device types
   - This is what the simulator currently teaches

3. Protocol-level exploitation
   - Modbus register manipulation
   - S7 memory reading and logic extraction
   - OPC UA tag enumeration
   - This is what the simulator currently demonstrates

The simulator currently focuses on steps 2-3 because those are unique to OT security. Step 1 is largely standard IT security, well-covered by existing resources. However, integrating step 1 would provide a more complete picture of real-world attack scenarios.

## Ponder's perspective

Ponder's testing journal included a note about what wasn't tested:

"The simulator demonstrates protocol-level vulnerabilities comprehensively. What it doesn't demonstrate is how attackers gain the network access necessary to exploit those protocols.

"In actual facilities, wireless and remote access provide that initial foothold. Rogue access points, vendor VPNs, cellular modems, Bluetooth sensors, each one is a bridge across the supposed air gap.

"These aren't protocol vulnerabilities. They're architectural vulnerabilities. They can't be patched. They require policy changes, process improvements, and vigilance against unauthorised devices.

"The simulator could be enhanced to demonstrate these attack vectors. Simulated wireless networks with weak credentials. Simulated vendor access with excessive privileges. Simulated cellular modems providing hidden internet access.

"This would complete the attack chain: wireless access leading to network access, leading to protocol access, leading to physical impact.

"Currently, the simulator assumes you already have network access. In reality, obtaining that access is often the first challenge attackers face."

## Educational value of future enhancements

Adding wireless and remote access scenarios to the simulator would teach:

For security professionals:
- Complete attack chain from initial access to impact
- How wireless vulnerabilities enable protocol attacks
- Why air gaps fail in practice
- How to assess wireless and remote access security

For operators and engineers:
- Why unauthorised wireless devices are dangerous
- How vendor access can be exploited
- Why air gaps require constant vigilance
- What secure remote access looks like

For management:
- Why wireless policy enforcement matters
- Why vendor access needs governance
- Cost-benefit of proper remote access solutions
- Risk of convenience-driven workarounds

## Current resources for wireless testing

Whilst the simulator doesn't currently cover wireless and remote access, several excellent resources exist:

Wireless security testing:
- Aircrack-ng suite for WiFi security testing
- Ubertooth One for Bluetooth analysis
- HackRF One for SDR-based protocol analysis
- Documented extensively in IT security literature

Remote access security:
- VPN security assessment methodologies
- Privileged access management best practises
- Vendor risk management frameworks
- Standard IT security audit procedures

The simulator's value is in teaching what these resources don't cover: industrial protocol security. Future enhancements could bridge the gap, showing how IT security vulnerabilities (wireless, remote access) lead to OT security impacts (protocol exploitation, physical consequences).

## Future development priorities

If wireless and remote access features were added to the simulator, priorities would be:

### Priority 1: Rogue access point scenario
- Educational value: High (very common in real facilities)
- Technical complexity: Moderate
- Integration with existing content: Good (provides initial access for protocol attacks)

### Priority 2: Vendor VPN scenario
- Educational value: High (common attack vector)
- Technical complexity: Moderate
- Integration with existing content: Excellent (demonstrates supply chain risk)

### Priority 3: Bluetooth sensor simulation
- Educational value: Moderate (increasingly common)
- Technical complexity: Low
- Integration with existing content: Good (demonstrates IoT security issues)

### Priority 4: Cellular modem discovery
- Educational value: Moderate (less common but high impact)
- Technical complexity: Low
- Integration with existing content: Good (demonstrates hidden access risk)

## Conclusion

The UU P&L simulator currently focuses on industrial protocol security, assuming the attacker already has network access to OT systems. This is a reasonable simplification that allows deep focus on protocol-level vulnerabilities.

However, real-world attacks begin with obtaining that network access, often through wireless or remote access vulnerabilities. Future simulator enhancements could include these attack vectors, providing a more complete picture of OT security assessment.

Until then, wireless and remote access security should be understood as complementary topics, covered by standard IT security resources but critically important for understanding complete attack chains in OT environments.

The air gap, in practice, is full of holes. Understanding what those holes look like and how to find them is essential for comprehensive OT security assessment.


Further reading:
- [Network Security](../vulnerabilities/network.md) - Reconnaissance and protocol fingerprinting
- [Workstation Security](../vulnerabilities/workstation.md) - Engineering access and entry points
- [Supply Chain Security](supply-chain.md) - Vendor access and remote connectivity

For wireless security testing tools and techniques, consult standard IT security resources. The simulator focuses on what happens after network access is obtained, not how that access is initially achieved.
