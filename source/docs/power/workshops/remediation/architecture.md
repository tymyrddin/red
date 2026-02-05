# Architecture and encryption

*Fundamental changes to how systems operate*

## Overview

These three challenges aren't quick fixes. They're architectural changes that affect how the entire system operates. They take planning, testing, and careful rollout. They also have the biggest security impact.

Expect these to be complex. Expect things to break. Expect to learn why OT security projects take months.

## Challenge 7: Encrypt SCADA communications

The problem: SCADA data travels in cleartext. Anyone with network access can intercept operational data, understand system behaviour, and plan attacks.

Your goal: Deploy OPC UA with signing and encryption. Make SCADA communications confidential and tamper-proof.

### What you can do

Configure OPC UA security policy:
```python
from components.security.encryption import OPCUACrypto, OPCUASecurityPolicy

# Change from None to encrypted
security_policy = OPCUASecurityPolicy.AES256_SHA256_RSAPSS
policy_uri = OPCUACrypto.get_security_policy_uri(security_policy)

# Enable signing and encryption
message_security = MessageSecurityMode.SignAndEncrypt
```

Generate and distribute certificates:
```python
from components.security.encryption import CertificateManager

cert_mgr = CertificateManager(cert_dir=Path("./certs"))

# Generate certificate for SCADA server
server_cert, server_key = cert_mgr.generate_self_signed_cert("scada.uu-power.local")
cert_mgr.save_certificate(server_cert, server_key, "scada_server")

# Generate certificates for each client (HMIs, engineering stations)
for client in ["hmi_1", "hmi_2", "engineering_1"]:
    cert, key = cert_mgr.generate_self_signed_cert(f"{client}.uu-power.local")
    cert_mgr.save_certificate(cert, key, client)
```

Implement certificate validation:
- Server validates client certificates
- Client validates server certificate
- Reject connections with invalid/expired certificates
- Handle trust chain

Measure performance impact:
- Baseline: measure connection time, read latency, write latency without encryption
- Encrypted: measure same operations with SignAndEncrypt
- Calculate overhead
- Is it acceptable for real-time operations?

### Test it

Security testing:
```bash
# Try to intercept traffic
tcpdump -i any -w capture.pcap port 4840

# Open in Wireshark - can you read data?
wireshark capture.pcap

# Should be encrypted, unreadable
```

Connection testing:
```bash
# Connect without certificate - should fail
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Connect with valid certificate - should succeed
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840 --cert client.pem --key client_key.pem

# Connect with expired certificate - should fail
```

Performance testing:
- Measure read/write latency
- Measure connection establishment time
- Test under load (many simultaneous connections)
- Is real-time performance still acceptable?

Operational testing:
- What happens when certificate expires?
- Can you renew without downtime?
- What's the emergency procedure when PKI fails?

### What you can learn

Encryption overhead:
- CPU cost of encryption/decryption
- Memory overhead
- Latency increase
- May not be acceptable for hard real-time systems

Certificate lifecycle management:
- Generation, distribution, installation
- Renewal before expiry
- Revocation when compromised
- Backup and recovery
- This is a full-time job in large deployments

PKI infrastructure requirements:
- Certificate Authority (even if self-signed)
- Certificate storage and backup
- Certificate distribution mechanism
- Monitoring for expiring certificates
- Revocation checking (CRL or OCSP)

Operational complexity:
- More moving parts
- More points of failure
- More things to monitor
- More maintenance burden

Trade-offs:
- Confidentiality vs performance
- Security vs complexity
- Protection vs operational risk

### Where to start

```bash
# Understand OPC UA encryption
cat components/security/README.md | sed -n '/### encryption.py/,/### anomaly_detector.py/p'

# Look at OPC UA security classes
grep -A 30 "class OPCUACrypto\|class OPCUASecurityPolicy" components/security/encryption.py

# Find OPC UA server implementation
find components/ -name "*opcua*" -type f

# Look at certificate management
grep -A 30 "class CertificateManager" components/security/encryption.py
```

### Going deeper

Questions to explore:
- How do you handle certificate expiry without downtime?
- What's your CA strategy (commercial, internal, self-signed)?
- How do you revoke compromised certificates?
- How do you handle legacy clients that don't support encryption?

Advanced options:
- Deploy internal PKI with proper CA
- Implement automated certificate renewal
- Deploy certificate monitoring and alerting
- Implement certificate pinning for additional security
- Test different security policies (Basic128Rsa15 vs Basic256Sha256)
- Measure and optimise performance
- Implement hardware security modules (HSMs) for key storage

## Challenge 8: Implement jump host architecture

The problem: Administrative access comes from anywhere on the corporate network. Compromised workstation = compromised OT. No centralised access control or monitoring.

Your goal: Deploy jump host (bastion) architecture. All administrative OT access flows through one controlled point.

### What you can do

Design the architecture:
```
Before:
Corporate Network ──→ Turbine PLC
                  ├─→ Reactor PLC
                  ├─→ SCADA
                  └─→ Safety PLC

After:
Corporate Network ──→ Jump Host ──→ Turbine PLC
                                 ├─→ Reactor PLC
                                 ├─→ SCADA
                                 └─→ Safety PLC

Direct access: BLOCKED by firewall
```

Deploy jump host:
- Hardened Linux server or Windows bastion
- Minimal software installed
- Strong authentication (certificates or MFA)
- Session recording enabled
- Logging all access

Configure firewall rules:
```bash
# Block direct access from corporate to OT
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.100.0/24 -j DROP

# Allow jump host to OT
iptables -A FORWARD -s 192.168.1.50 -d 192.168.100.0/24 -j ACCEPT

# Allow corporate to jump host
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.50 -j ACCEPT
```

Integrate authentication:
```python
# Jump host authenticates using AuthenticationManager
# Records all sessions
# Enforces authorisation before allowing connections
```

Create break-glass procedure:
- What happens when jump host fails?
- Emergency bypass procedure
- Documented, audited, infrequent
- Temporary firewall rule modification
- Automatic revert after emergency

### Test it

Access control testing:
```bash
# Try direct access to PLC - should be blocked
telnet 192.168.100.10 502

# Try via jump host - should succeed
ssh jump-host
telnet 192.168.100.10 502
```

Bypass testing:
- Can you bypass jump host?
- Spoof source IP?
- Use different protocol?
- Find misconfigured firewall rule?

Failure scenario testing:
- Stop jump host service
- Can you still access OT? (should not, except emergency)
- Activate break-glass procedure
- Verify emergency access works
- Verify automatic revert

Usability testing:
- How does this affect operator workflow?
- How long does it take to connect?
- Is it practical for frequent access?
- Do people try to work around it?

### What you can learn

Single point of failure:
- Jump host down = no administrative access
- Need high availability (redundant jump hosts)
- Need emergency procedures
- But emergency procedures can be abused

Centralised control benefits:
- All access logged in one place
- Consistent authentication and authorisation
- Session recording for audit
- Easier to monitor for abuse

Usability impact:
- Extra hop for every connection
- More complex for users
- Resistance from operators
- Training required

Break-glass procedures:
- Need emergency access mechanism
- But emergency access can be abused
- Need monitoring and audit
- Difficult balance

### Where to start

```bash
# This challenge requires architectural planning
# No single component to use - you're building infrastructure

# Consider jump host software options:
# - SSH bastion with session recording
# - RDP gateway
# - PAM solution (Privileged Access Management)

# Plan firewall rules
# Map current access patterns
# Design new access patterns through jump host
# Test in lab before production

# Read about jump host patterns
# Search: "bastion host OT" "jump server ICS"
```

### Going deeper

Questions to explore:
- How do you make jump host highly available?
- What's the monitoring strategy for jump host?
- How do you handle vendor remote access?
- What about third-party vendors who need temporary access?

Advanced options:
- Deploy redundant jump hosts for HA
- Implement PAM solution with full session recording
- Deploy jump host in DMZ for vendor access
- Implement just-in-time access (request approval, get temporary access)
- Deploy different jump hosts for different privilege levels
- Implement geofencing (only allow access from specific locations)

## Challenge 9: Network segmentation (IEC 62443 zones)

The problem: Everything is on one flat network. Compromised corporate workstation = access to safety systems. No network-level isolation. One breach compromises everything.

Your goal: Design and implement zone-based architecture following IEC 62443. Separate safety from production. Isolate corporate IT from OT.

### What you can do

Design zone architecture:
```
IEC 62443 Zones:

Level 3 (Enterprise): Corporate IT, ERP, Email
    ↓ (Conduit: DMZ with firewalls)
Level 2 (Supervision): SCADA, HMI, Historian
    ↓ (Conduit: Industrial firewall)
Level 1 (Control): PLCs, Controllers
    ↓ (Conduit: Process network)
Level 0 (Process): Sensors, Actuators, Field devices

Safety Zone (parallel): Safety PLC, Safety I/O
    ↓ (Isolated, minimal conduits)
```

Map systems to zones:
- Level 0: Turbine sensors and actuators, reactor instrumentation
- Level 1: Turbine PLCs, Reactor PLC
- Level 2: SCADA servers (primary and backup), HMIs
- Level 3: Engineering workstations, management systems
- Safety: Safety PLC (separate zone, minimal connectivity)

Define conduits (allowed communications):
```
Allowed:
- Level 2 → Level 1: SCADA reads PLC data, HMI writes setpoints
- Level 3 → Level 2: Engineering access to SCADA (via jump host)
- Level 1 → Level 0: PLC controls field devices

Blocked:
- Level 3 → Level 1: No direct engineering to PLC
- Level 3 → Level 0: No direct corporate to field devices
- Any → Safety Zone: Minimal, tightly controlled

Exception: Safety Zone → Level 1: Safety interlocks
```

Implement segmentation:
- Option 1: VLANs with Layer 3 routing and firewall
- Option 2: Physical network separation
- Option 3: Industrial firewalls between zones

Configure firewall rules:
```bash
# Example rules (simplified)
# Level 2 to Level 1: Allow Modbus, S7
iptables -A FORWARD -s 192.168.2.0/24 -d 192.168.1.0/24 -p tcp --dport 502 -j ACCEPT
iptables -A FORWARD -s 192.168.2.0/24 -d 192.168.1.0/24 -p tcp --dport 102 -j ACCEPT

# Level 3 to Level 2: Allow OPC UA via jump host only
iptables -A FORWARD -s 192.168.3.50 -d 192.168.2.0/24 -p tcp --dport 4840 -j ACCEPT
iptables -A FORWARD -s 192.168.3.0/24 -d 192.168.2.0/24 -j DROP

# Safety zone: tightly restricted
iptables -A FORWARD -d 192.168.99.0/24 -j DROP  # Default deny
iptables -A FORWARD -s 192.168.99.10 -d 192.168.1.0/24 -p tcp --dport 502 -j ACCEPT  # Only safety PLC to control PLCs
```

### Test it

Segmentation testing:
```bash
# From corporate (Level 3), try to reach PLC (Level 1) - should fail
ping 192.168.1.10

# From SCADA (Level 2), try to reach PLC - should succeed
ping 192.168.1.10

# From anywhere, try to reach safety zone - should fail
ping 192.168.99.10
```

Pivot testing:
- Compromise corporate workstation (Level 3)
- Can you reach Level 2?
- Can you reach Level 1?
- Can you reach safety zone?
- Where does segmentation stop you?

Operational testing:
- Can operators use HMI?
- Can engineers program PLCs?
- Can maintenance access systems?
- What workflows break?

Legitimate cross-zone requirements:
- Historian needs data from all PLCs
- Engineering needs to program PLCs
- Vendor needs remote access
- How do you handle these?

### What you can learn

Zone architecture is complex:
- Every system needs to be in a zone
- Every communication needs to be in a conduit
- Exceptions multiply
- Change management becomes critical

Operational impact is huge:
- Workflows change
- Some things become harder
- Need new procedures
- Training required

Perfect segmentation is impossible:
- Always need some cross-zone communication
- Historian, engineering access, vendor access
- Each conduit is a potential attack path
- Defence in depth, not perfect isolation

Implementation challenges:
- Existing infrastructure wasn't designed for zones
- Retrofitting is expensive
- Switch/firewall replacements
- Cable runs
- Downtime for cutover

Trade-offs everywhere:
- Security vs operational flexibility
- Isolation vs necessary communication
- Cost vs protection
- Complexity vs usability

### Where to start

```bash
# This is the most complex challenge
# Start with planning, not implementation

# Step 1: Map current network
# - What systems exist?
# - How do they communicate?
# - What protocols?
# - Draw current architecture

# Step 2: Design zones
# - Assign each system to a zone
# - Define security requirements per zone
# - Identify required conduits

# Step 3: Plan implementation
# - What hardware is needed?
# - What changes to systems?
# - Downtime requirements?
# - Testing approach?

# Read IEC 62443 documentation
# Search: "IEC 62443 zones and conduits"
```

### Going deeper

Questions to explore:
- How do you handle systems that span zones (historian)?
- What's the firewall change management process?
- How do you test firewall rules without breaking production?
- How do you handle new systems (which zone? which conduits)?

Advanced options:
- Deploy industrial firewalls with deep packet inspection
- Implement unidirectional gateways for critical isolation
- Deploy DMZ for vendor remote access
- Implement micro-segmentation within zones
- Deploy IDPS (Intrusion Detection/Prevention) at zone boundaries
- Implement protocol whitelisting at firewalls
- Deploy application-layer gateways for protocol inspection

Phased implementation:
Don't try to do everything at once. Implement in phases:

1. Phase 1: Separate corporate (Level 3) from OT (Level 1-2)
2. Phase 2: Separate SCADA (Level 2) from PLCs (Level 1)
3. Phase 3: Isolate safety zone
4. Phase 4: Micro-segmentation within zones

Test each phase thoroughly before proceeding.

## Combining architectural challenges

If you're ambitious, implement all three:

1. Encryption: SCADA communications are confidential
2. Jump host: Administrative access is centralised
3. Segmentation: Zones limit lateral movement

The result: Defence in depth architecture
- Network segmentation limits attack surface
- Jump host controls and monitors administrative access
- Encryption protects data in transit
- Compromising one layer doesn't compromise all

Test the combination:
- Simulate attack from corporate network
- How far can you get?
- Which defences stop you?
- What's the attack path?

Understand the costs:
- Implementation time (months)
- Hardware costs (firewalls, switches, jump hosts)
- Operational complexity
- Maintenance burden
- Training requirements

Is it worth it? Depends on your risk tolerance and asset value.

---

*"Anyone can make a system secure by making it unusable. The skill is making it secure and usable. That requires architecture." - Ponder Stibbons*