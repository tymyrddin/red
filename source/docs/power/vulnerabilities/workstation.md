# Engineering Workstation Security: The Royal Road Not Taken

![Engineering workstation](/_static/images/ot-engineering-workstation.png)

*Or: Why The Simulator Doesn't Include The Easiest Path In*

## The privileged access point

Engineering workstations, Ponder understood, were the crown jewels of OT security assessments. They were computers used to programme PLCs, configure SCADA systems, and maintain industrial infrastructure. They had legitimate access to everything. They contained project files with complete system documentation. They stored credentials for accessing industrial devices. They bridged between corporate and OT networks.

They were also, typically, the least secure systems in the entire environment.

If you want to compromise an OT environment, experienced attackers know: don't bother with fancy PLC exploits or protocol fuzzing. Just compromise an engineering workstation. It's easier, more effective, and gives you everything you need.

## The workstations in the simulator

The UU P&L simulator includes several workstations in its architecture:
- 4 HMI operator workstations (Wonderware InTouch)
- 1 engineering/programming workstation
- 1 finance workstation (enterprise zone, phishing target)

However, the simulator focuses on protocol-level vulnerabilities rather than endpoint security testing. The workstations exist in the architecture but aren't the primary testing focus because:

Engineering workstation security is, fundamentally, endpoint security. It's Windows patching, antivirus configuration, user account management, and all the other IT security practices that apply to any workstation.

What makes workstations dangerous in OT isn't that they're technically different from IT workstations. It's that they have privileged access to industrial systems and are often poorly secured despite that access.

We may wish to expand the simulation for entry-points like this.

## What workstation testing could find

Whilst the simulator includes workstations in its architecture, it doesn't implement endpoint vulnerability testing. If such testing were added, assessment would likely reveal:

Operating System Issues:
- Windows 7 or older (end of life, unpatched)
- Missing security updates (hundreds or thousands of patches behind)
- Administrative privileges for regular users
- No disk encryption
- Antivirus disabled (because it "interfered with engineering tools")

Software Vulnerabilities:
- Outdated Java, Adobe Reader, browsers
- Engineering software requiring specific (old) Windows versions
- Multiple versions of programming tools installed
- Development/debugging tools left installed

Credential Management:
- Passwords stored in plain text files
- Project files containing PLC passwords
- Saved remote desktop connections with embedded credentials
- Browser password stores full of OT system credentials

Network Configuration:
- Connected to both corporate and OT networks simultaneously
- VPN connections to vendor support networks
- Remote access tools (TeamViewer, VNC) with weak passwords
- File shares with no access control

These are all real findings from real OT security assessments. They're also all standard IT security issues, just with higher consequences because the compromised workstation has access to industrial systems.

## The attack path

The typical attack sequence involving engineering workstations:

1. Initial compromise: Attacker gains access to corporate IT network (phishing, vulnerability, etc.)
2. Lateral movement: Attacker finds engineering workstation on network
3. Workstation compromise: Exploit unpatched vulnerabilities or weak credentials
4. Credential harvesting: Extract stored passwords, project files, configurations
5. OT network access: Use engineering workstation's legitimate connections to reach OT systems
6. Industrial system compromise: Use harvested credentials and engineering tools to attack PLCs/SCADA

The engineering workstation is step 3-5 in this chain. It's the bridge from IT to OT, and it's often poorly defended.

## Why the simulator starts at step 6

The UU P&L simulator assumes the attacker has already reached step 6: they have network access to industrial protocols and can communicate with PLCs and SCADA systems directly.

This isn't because steps 1-5 are unimportant. It's because:

Steps 1-5 are IT security: Compromising workstations, extracting credentials, and lateral movement are well-covered in IT security training and penetration testing resources.

Step 6 is uniquely OT: Understanding industrial protocols, crafting appropriate commands, and manipulating control systems without triggering alarms or causing damage is the specialised knowledge that OT security requires.

The simulator teaches step 6. Standard IT security resources cover steps 1-5 adequately.

## What you won't learn here

Testing the simulator won't teach you:
- How to exploit Windows vulnerabilities
- How to perform pass-the-hash attacks
- How to extract credentials from memory
- How to pivot through network segments
- How to identify engineering workstations on a network

These are penetration testing fundamentals, covered extensively in IT security training.

## What you can learn

What the simulator does teach is what to do once you've compromised the workstation and gained access to OT protocols:
- How to interact with S7 PLCs using Snap7
- How to read and write Modbus registers
- How to browse OPC UA servers
- How to enumerate EtherNet/IP tags
- How to extract programme blocks from PLCs
- How to reconnaissance SCADA systems

These are the skills that differentiate OT security from IT security.

## The realistic threat model

In real OT security assessments, engineering workstation compromise is often trivial:
- They run obsolete operating systems
- They're missing years of security patches
- They have weak or default credentials
- They're connected to corporate networks where attackers have already gained access

Once compromised, they provide:
- Network access to OT systems
- Credentials for PLCs and SCADA
- Engineering software for legitimate-looking access
- Complete documentation of system architecture

The hard part isn't compromising the workstation. The hard part is knowing what to do with that access: which protocols to use, which commands to send, which systems to target, and how to avoid detection.

## The deliberate focus

Ponder's testing notes concluded: "Engineering workstations are Windows boxes with privileged access. Compromising them is IT security. Knowing what to do after compromising them is OT security.

"The simulator teaches the second part. If you need to learn the first part, there are excellent IT security resources available. But understanding how to programme a PLC, what Modbus registers control physical outputs, how OPC UA security policies work, and how to reconnaissance industrial systems without triggering alarms... that's what makes OT security its own discipline.

"That's what the simulator demonstrates."

Further Reading:
- [PLC Security Testing](plc.md) - What to do with PLC access
- [SCADA Security Testing](scada.md) - Exploiting SCADA protocols
- [Network Security](network.md) - Discovering industrial systems

For engineering workstation compromise techniques, refer to standard penetration testing resources. The simulator 
focuses on industrial protocol security, assuming network access has already been achieved.

The unique value of the simulator is teaching what happens after traditional IT security techniques have succeeded: 
how to interact with industrial systems in ways that achieve attacker objectives whilst avoiding detection and 
preventing unintended damage.
