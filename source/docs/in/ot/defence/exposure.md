# Reducing OT attack surface

OT attack surface reduction is primarily an architecture problem, not a patching problem. The exposure that enables IT-to-OT pivot attacks is almost always a network design issue: routes that exist without review, firewall rules that were never tightened after initial commissioning, and shared engineering workstations that bridge security zones.

## Network segmentation

The IT/OT boundary should be enforced by a firewall with an explicit permit list, not an implicit deny with accumulated exceptions. Every rule permitting traffic from IT to OT should document its business justification, the specific source and destination addresses, the specific ports, and the date it was last reviewed.

A data diode enforces unidirectional data flow from OT to IT for historian data replication. Process data flows outward for reporting; no traffic flows inward. Data diodes eliminate the class of attack that reaches OT by exploiting historian connectivity, at the cost of requiring unidirectional replication architectures (which are supported by modern historian products).

Historian servers should not have direct routes to Level 2 SCADA servers. The historian's data interfaces should be inbound-only: a Level 2 SCADA interface pushes data to the historian over a controlled channel; the historian does not poll Level 2 systems directly.

Engineering workstations should not be multi-homed across security zones. A workstation used for corporate IT tasks (email, web browsing) should not also connect to Level 2 PLC networks. Dedicated engineering workstations that have no corporate IT connectivity should be used for all PLC programming and maintenance. If remote engineering access is required, it should go through a dedicated, audited jump host, not through the corporate VPN to a multi-homed laptop.

## Remote access hardening

Vendor remote access should be time-limited and session-monitored. No vendor account should have permanent always-on access. Vendor sessions should be proxied through a gateway that records session content, and every session should require explicit approval from an OT operator before connection is permitted.

VPN credentials for OT access should be separate from corporate IT credentials and subject to multi-factor authentication. OT VPN connections should permit access only to the specific jump host, not to the broader OT network.

Disable or remove remote desktop and remote management interfaces from PLCs, RTUs, and HMI servers that do not require them. Industrial protocols should not be accessible from the IT network; only the historian's data interfaces should cross the boundary.

## Protocol authentication

Modbus and DNP3 carry no authentication in their base specifications. Where feasible, enforce network-level access controls that restrict which IP addresses can send traffic to OT protocol ports. On managed switches in the OT network, MAC address filtering and port security prevent new devices from communicating.

OPC UA should be deployed with SecurityMode set to `SignAndEncrypt` and client certificate validation enforced. Accepting self-signed certificates or deploying in `None` mode defeats the authentication entirely.

For environments that cannot retrofit authentication to existing protocols, unidirectional security gateways or application-layer firewalls that inspect OT protocol traffic and permit only expected function codes from expected addresses provide a compensating control.

## Patch management

OT patch management is constrained by availability requirements: patching a PLC requires taking the controlled process offline. The practical approach is to patch during scheduled maintenance windows, to prioritise patches for internet-facing and IT-boundary systems (historians, HMIs, jump hosts), and to ensure that engineering workstations running corporate software (Office, browser, email client) are patched on the IT schedule even if the OT engineering software cannot be updated.
