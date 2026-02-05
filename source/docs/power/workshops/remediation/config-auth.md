# Configuration and authentication

*The "easy" fixes that turn out to be complicated*

## Overview

These three challenges involve adding authentication and logging to systems that currently have none. The components exist. The challenge is integrating them without breaking everything.

Start here if you want quick wins or are new to OT security hardening.

## Challenge 1: Password protect the SCADA

The problem: UU Power & Light's SCADA servers accept anonymous connections. Anyone can browse operational data.

Your goal: Enable OPC UA authentication so only authorised clients can connect.

### What you can do

Configure security policy:
- Change OPC UA from `SecurityPolicy.None` to something requiring authentication
- Choose appropriate security policy (Basic128Rsa15, Basic256, Basic256Sha256)
- Consider: Start with `MessageSecurityMode.Sign` before `SignAndEncrypt`

Generate certificates:
- Use `encryption.py` to generate certificates for server and clients
- Configure certificate trust (which clients are trusted?)
- Handle certificate storage and distribution

Update server configuration:
- Modify OPC UA server to require authentication
- Configure certificate validation
- Handle connection rejection for untrusted clients

Update client scripts:
- Modify HMI and SCADA clients to present certificates
- Handle authentication failures
- Implement certificate renewal logic

### Test it

Security testing:
```bash
# Try anonymous access - should fail
python scripts/vulns/opcua_readonly_probe.py --endpoint opc.tcp://127.0.0.1:4840

# Try with invalid certificate - should fail
# Try with valid certificate - should succeed
```

Operational testing:
- Can legitimate HMI connect?
- What happens when certificate expires?
- Can operators still monitor systems during certificate issues?

Break it on purpose:
- Delete a certificate
- Use expired certificate
- Connect from unauthorised client
- What's the operator experience when authentication fails?

### What you can learn

Certificate management is complex:
- Generation, distribution, storage, renewal, revocation
- PKI infrastructure requirements
- Who manages certificates in operational environment?

What breaks:
- Legacy clients that don't support authentication
- Scripts and automation that assume anonymous access
- Vendor remote access that needs reconfiguration
- Emergency access scenarios

Trade-offs:
- Security vs operational complexity
- Certificate lifecycle management burden
- Recovery procedures when authentication fails

### Where to start

```bash
# Read about OPC UA security
cat components/security/README.md | grep -A 40 "### encryption.py"

# Look at certificate generation
grep -A 20 "class CertificateManager" components/security/encryption.py

# Check current SCADA configuration
cat simulation.yml | grep -A 10 opcua

# Find OPC UA server implementation
find components/ -name "*opcua*.py" | head -5
```

### Going deeper

Questions to explore:
- How do you handle certificate expiry without downtime?
- What's the emergency access procedure when certificates fail?
- How do you manage dozens or hundreds of client certificates?
- What's the performance impact of certificate validation?

Advanced options:
- Implement certificate revocation checking
- Deploy certificate management automation
- Configure certificate-based user authentication (not just client authentication)
- Implement security policy negotiation

## Challenge 2: Implement RBAC

The problem: Everyone who can access the network has full control. No distinction between viewers, operators, engineers, and supervisors.

Your goal: Create role-based access control. Operators can monitor and control. Engineers can configure. Supervisors can do safety-critical operations.

### What you can do

Define roles:
- Use `authentication.py` role system (VIEWER, OPERATOR, ENGINEER, SUPERVISOR, ADMIN)
- Decide what permissions each role needs
- Map roles to real operational positions

Create users:
```python
# Example user creation
auth = AuthenticationManager()
await auth.create_user("operator1", UserRole.OPERATOR, full_name="Jane Operator")
await auth.create_user("engineer1", UserRole.ENGINEER, full_name="Bob Engineer")
await auth.create_user("supervisor1", UserRole.SUPERVISOR, full_name="Alice Supervisor")
```

Integrate authorisation checks:
- Find control operations in device code (turbine speed, reactor controls, safety bypasses)
- Add authorisation checks before executing operations
- Handle authorisation failures gracefully

Assign permissions:
- Map operations to permissions (PermissionType.CONTROL_SETPOINT, SAFETY_BYPASS, etc.)
- Decide who can do what to which systems
- Consider: Do all turbines have same permissions? Or different?

### Test it

Permission testing:
```bash
# Try to change turbine speed as operator - should succeed
# Try to bypass safety as operator - should fail
# Try to modify configuration as operator - should fail
# Try all above as engineer - which succeed?
```

Bypass testing:
- Can you circumvent authorisation checks?
- What if you modify the database directly?
- What if you use protocol-level access instead of API?

Usability testing:
- Are permissions too restrictive?
- Are permissions too permissive?
- Can operators do their jobs?
- What happens when permissions are wrong during emergency?

### What you can learn

Permission granularity is hard:
- Too coarse: operators have too much access
- Too fine: constant authorization failures, unusable
- Where's the right balance?

Where to enforce:
- Client-side? Can be bypassed
- Server-side? Every endpoint needs checks
- Protocol-level? Most secure but most complex

Role design challenges:
- Real operational roles don't map cleanly to RBAC
- Special cases and exceptions multiply
- Emergency scenarios need overrides

The two-person problem:
- Some operations need two people
- How do you implement that?
- What's the usability impact?

### Where to start

```bash
# Understand authentication system
cat components/security/README.md | sed -n '/### authentication.py/,/### encryption.py/p'

# Look at roles and permissions
grep "class UserRole\|class PermissionType" components/security/authentication.py

# Find control operations to protect
grep -r "def write_\|def control_\|def set_" components/devices/ | head -20

# See authorization examples
grep -A 10 "authorize(" components/security/authentication.py
```

### Going deeper

Questions to explore:
- How do you handle role changes (operator promoted to engineer)?
- What's the approval process for permission grants?
- How do you audit who did what?
- What about temporary elevated privileges?

Advanced options:
- Implement attribute-based access control (ABAC) for more flexibility
- Deploy time-based permissions (different access during maintenance windows)
- Implement location-based access (only from control room)
- Create approval workflows for sensitive operations

## Challenge 3: Deploy logging and auditing

The problem: You can't detect attacks you don't log. Currently, operations happen without audit trails. When things go wrong, there's no forensic evidence.

Your goal: Integrate structured logging to capture all security-relevant events.

### What you can do

Integrate logging system:
```python
from components.security.logging_system import get_logger, EventSeverity, EventCategory

logger = get_logger(__name__, device="turbine_plc_1")
```

Log security events:
- Authentication attempts (success and failure)
- Authorization failures
- Configuration changes
- All write operations (Modbus writes, OPC UA writes, S7 writes)
- Safety system interactions

Log operational events:
- Setpoint changes (who, what, when, from what to what)
- Mode changes (auto to manual, etc.)
- Alarms and events
- System starts and stops

Create audit trails:
```python
await logger.log_audit(
    "Setpoint changed",
    user="operator1",
    action="write_setpoint",
    resource="turbine_1",
    old_value=1500.0,
    new_value=1600.0,
    result="ALLOWED"
)
```

### Test it

Coverage testing:
```bash
# Run your Modbus attack - is it logged?
python scripts/exploitation/turbine_overspeed_attack.py

# Check logs
grep "turbine\|setpoint\|write" /path/to/logs/*.log

# Change speed through HMI - can you trace who did it?
# Bypass safety - is it logged?
```

Volume testing:
- How much log data is generated?
- Is it too much? Too little?
- Can you find relevant events?
- How fast do logs fill disk?

Analysis testing:
- Can you detect reconnaissance in logs?
- Can you detect attack progression?
- Can you identify attacker techniques?

### What you can learn

What to log:
- Not everything (too much noise)
- Not too little (miss attacks)
- Security-relevant events vs operational noise
- Cost of logging (performance, storage, analysis)

Log analysis is hard:
- Finding needles in haystacks
- Signal vs noise ratio
- Real-time detection vs forensic analysis
- Need for SIEM/log aggregation

Audit trail requirements:
- Who, what, when, where, why
- Before/after values
- Success and failure
- Tamper protection

Performance impact:
- Synchronous logging slows operations
- Asynchronous logging can lose events
- Log rotation and retention
- Network overhead for remote logging

### Where to start

```bash
# Understand ICS logging
cat components/security/README.md | sed -n '/### logging_system.py/,/### authentication.py/p'

# Look at event types
grep "class EventCategory\|class EventSeverity\|class AlarmPriority" components/security/logging_system.py

# Find operations to log
grep -r "def write_\|def control_\|def set_" components/devices/ | head -20

# Check logging configuration
grep -A 10 "logging" simulation.yml
```

### Going deeper

Questions to explore:
- How long do you retain logs?
- Who has access to logs?
- How do you protect logs from tampering?
- How do you correlate events across systems?

Advanced options:
- Deploy SIEM integration
- Implement real-time log analysis
- Create detection rules for common attacks
- Develop log-based alerting
- Implement secure log forwarding
- Deploy log integrity checking (digital signatures)

## Common patterns across all three

The authentication spiral:
1. Add authentication
2. Something breaks
3. Add exception for broken thing
4. Another thing breaks
5. Add another exception
6. Now you have complex authentication with many exceptions

The usability problem:
- Secure = unusable
- Usable = insecure
- Finding balance requires iteration

The emergency scenario:
- All your security assumes normal operations
- Emergencies are not normal
- Need break-glass procedures
- But break-glass can be abused

## Combining challenges

Try implementing all three together:
- Authentication (who are you?)
- Authorization (what can you do?)
- Logging (what did you do?)

This is the security triad for accountability.

Test the combination:
- Can you trace every action to a user?
- Can you prevent unauthorised actions?
- Can you detect attacks in progress?
- Can operators still do their jobs?

---

*"Adding passwords is easy. Making password-protected systems usable is hard. Making them usable during emergencies whilst preventing abuse - that's the real challenge." - Ponder Stibbons (probably)*
