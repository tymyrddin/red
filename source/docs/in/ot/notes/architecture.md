# IT/OT convergence and the air gap myth

The air gap is largely folklore in modern industrial environments. Remote monitoring, predictive maintenance, regulatory reporting, and vendor support all require connectivity between operational networks and corporate IT or the internet. What exists in most organisations is not an air gap but a boundary: sometimes a firewall, sometimes a data diode, sometimes just a VLAN and the assumption that nobody would configure a route across it.

The dominant entry path into OT is through IT. Threat actors do not start in the OT network; they start in a phishing email, a VPN credential, or a compromised corporate workstation, and they move toward OT once they understand the network topology. The question for a red team is not how to exploit a PLC directly but how to travel from an initial foothold to a position where process manipulation is possible.

## The Purdue model in practice

The Purdue Enterprise Reference Architecture describes five levels of an industrial network, with the intent that communication between levels is controlled and audited. In practice:

Level 0 and 1 (field devices and PLCs) communicate over industrial protocols: Modbus, Profibus, DNP3, EtherNet/IP, and similar. These protocols carry no authentication and no encryption. Any host with a network path to a PLC on port 502 can send valid Modbus commands.

Level 2 (supervisory control and HMI) runs Windows-based HMI software connecting to PLCs. These Windows hosts are often running outdated OS versions with limited patching, because patching requires process downtime that operations teams resist. They may also run software that requires specific Windows versions or disables certain security controls.

Level 3 (operations and historian) is where IT and OT overlap most heavily. Historian servers such as OSIsoft PI collect process data from Level 2 and make it available to business intelligence and reporting systems in IT. This layer is the typical IT/OT boundary crossing point.

The IT/OT DMZ, where it exists, contains firewall rules that are often not reviewed after initial deployment. Rules permitting traffic from IT to the historian are intended; rules that accumulated over time permitting traffic from IT all the way to Level 2 are not always intentional and are often present.

## Remote access as the primary attack surface

Vendor remote access is the softest entry point in most OT environments. Equipment vendors require remote connectivity for support, troubleshooting, and firmware updates. This connectivity is often implemented through:

Always-on VPN tunnels with shared credentials that have not changed since installation. Remote desktop sessions to jump hosts in the DMZ with weak passwords. Vendor-specific remote access tools (TeamViewer, AnyDesk, or vendor proprietary clients) installed on engineering workstations. Web-based portals for HMI access exposed on the organisation's internet-facing IP range.

Remote access accounts tend to be over-permissioned (vendors request broad access for convenience) and under-monitored (OT operations teams do not have the same monitoring capability as IT security teams). Compromising a vendor's support account frequently provides more direct access to Level 2 systems than any other path.

## BYOD and the IT/OT crossover

Engineers often use the same laptop for both corporate IT tasks and OT engineering work. This laptop bridges the two networks: it holds OT engineering software (TIA Portal, Studio 5000, GE ToolboxST), project files, PLC credentials, and corporate email and VPN client simultaneously. Compromising this device provides both a foothold in IT and a ready-equipped engineering workstation capable of deploying modified PLC logic.

The BYOD pattern is worse: a personal laptop used for remote engineering work from home connects to the corporate VPN and from there directly to the OT engineering network. The personal laptop has no corporate EDR, no patching cadence controlled by IT, and may have other software installed that creates additional vulnerability exposure.
