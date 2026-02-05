# Detection and monitoring

*Because you can't prevent everything*

## Overview

Authentication and access control fail. Systems get compromised. Insiders abuse privileges. This is why detection matters.

These three challenges build detection and monitoring capabilities: anomaly detection, protocol filtering, and session management.

## Challenge 4: Anomaly detection deployment

**The problem:** Attacks look like normal operations at the protocol level. Modbus write is Modbus write. You need behavioural detection to spot abnormal patterns.

**Your goal:** Configure anomaly detection to identify abnormal turbine behaviour.

### What you'll do

**Establish baselines:**
```python
from components.security.anomaly_detector import AnomalyDetector

detector = AnomalyDetector(data_store, system_state)

# Learn normal turbine behaviour
await detector.add_baseline("turbine_1", "speed", learning_window=1000)
await detector.add_baseline("turbine_1", "temperature", learning_window=1000)
await detector.add_baseline("turbine_1", "pressure", learning_window=1000)
```

**Set range limits:**
```python
# Speed should be 800-1800 RPM
await detector.set_range_limit("turbine_1", "speed", min_value=800.0, max_value=1800.0)

# Temperature should be 20-100°C
await detector.set_range_limit("turbine_1", "temperature", min_value=20.0, max_value=100.0)
```

**Set rate-of-change limits:**
```python
# Speed shouldn't change faster than 10 RPM/second
await detector.set_rate_of_change_limit("turbine_1", "speed", max_rate=10.0)

# Temperature shouldn't spike rapidly
await detector.set_rate_of_change_limit("turbine_1", "temperature", max_rate=2.0)
```

**Integrate detection:**
- Check every sensor reading
- Generate alerts on anomalies
- Log anomalies for investigation

### Test it

**Attack detection:**
```bash
# Run overspeed attack - is it detected?
python scripts/exploitation/turbine_overspeed_attack.py --target-speed 1800

# Try gradual attack - at what rate is it detected?
python scripts/exploitation/turbine_overspeed_attack.py --target-speed 1800 --step-size 2

# Emergency stop - should this be detected as anomaly?
python scripts/exploitation/turbine_emergency_stop.py
```

**False positive testing:**
- Run normal operations for an hour
- How many false alarms?
- Are they actionable?
- Would operators start ignoring them?

**Tuning:**
- Adjust sigma threshold (default 3.0)
- Adjust learning window
- Adjust rate limits
- Find balance between detection and noise

### What you'll learn

**Baseline establishment:**
- How long to learn normal behaviour?
- What if operations change?
- How do you handle multiple operating modes?
- When to retrain baselines?

**False positive rate:**
- Too sensitive: alarm fatigue, operators ignore alerts
- Too insensitive: miss attacks
- No perfect threshold
- Need tuning for each system

**Attack detection is hard:**
- Sophisticated attacks stay within normal ranges
- Gradual attacks harder to detect than sudden ones
- Legitimate operations can look like attacks (emergency stops)
- Need multiple detection methods

**Operational context matters:**
- Maintenance creates anomalies
- Startup/shutdown are abnormal by definition
- Seasonal variations
- Load following creates variability

### Where to start

```bash
# Understand anomaly detection
cat components/security/README.md | sed -n '/### anomaly_detector.py/,/## Integration/p'

# Look at detection methods
grep "class AnomalyType\|async def check_value\|async def set_range_limit" components/security/anomaly_detector.py

# Find turbine parameters to monitor
grep -r "speed\|temperature\|pressure" components/devices/turbine* | grep "def \|property"

# Check current values to understand normal range
# (Run simulator and observe)
```

### Going deeper

**Questions to explore:**
- How do you handle different operating modes (startup, normal, shutdown)?
- What about seasonal patterns (summer vs winter load)?
- How do you detect coordinated attacks across multiple systems?
- Can you detect reconnaissance (scanning, probing)?

**Advanced options:**
- Implement pattern recognition for attack sequences
- Deploy machine learning for more sophisticated detection
- Correlate anomalies across multiple systems
- Implement time-of-day and day-of-week baselines
- Detect alarm flooding as attack indicator
- Implement protocol anomaly detection (malformed messages, unusual sequences)

## Challenge 5: Protocol-level filtering

**The problem:** Modbus allows any function code. S7 exposes complete memory. Even with authentication, you want defense in depth.

**Your goal:** Implement protocol-level restrictions on dangerous operations.

### What you'll do

**Modbus function code filtering:**
- Allow read operations (function codes 1, 2, 3, 4)
- Restrict write operations (function codes 5, 6, 15, 16)
- Allow writes only from specific IPs (HMI, engineering station)
- Block writes from unknown sources

**S7 connection filtering:**
- Whitelist allowed client IPs
- Restrict access to specific rack/slot combinations
- Allow read operations, restrict writes
- Block CPU control operations (start/stop)

**Implementation approaches:**
```python
# Option 1: In protocol handler
def handle_modbus_request(function_code, source_ip):
    if function_code in [5, 6, 15, 16]:  # Write operations
        if source_ip not in ALLOWED_WRITERS:
            log_security_event("Unauthorized write attempt", source=source_ip)
            return error_response()
    # Process normally

# Option 2: Firewall-style rules
rules = {
    "modbus": {
        "allow_read": "any",
        "allow_write": ["192.168.1.10", "192.168.1.11"],  # HMI and engineering
        "block_by_default": True
    }
}
```

### Test it

**Reconnaissance testing:**
```bash
# Read operations - should work
python scripts/recon/modbus_identity_probe.py
python scripts/vulns/modbus_coil_register_snapshot.py

# Write operations from unauthorized IP - should fail
python scripts/exploitation/turbine_overspeed_attack.py
```

**Bypass testing:**
- Can you spoof allowed IP?
- Can you use different protocol to same system?
- Can you exploit gaps in filtering rules?

**Operational testing:**
- Can HMI control turbines?
- Can engineering station program PLCs?
- Can vendor connect remotely?
- What breaks?

### What you'll learn

**Protocol-specific controls:**
- Each protocol has different risk areas
- Modbus: function codes
- S7: memory areas and CPU control
- OPC UA: method calls and write access
- EtherNet/IP: tag writes

**Defense in depth:**
- Multiple layers of control
- Authentication + protocol filtering + network segmentation
- No single control is sufficient

**Whitelisting vs blacklisting:**
- Whitelist: allow only known good
- Blacklist: block known bad
- Whitelist more secure but higher operational overhead

**Operational flexibility vs security:**
- Strict filtering: secure but inflexible
- Loose filtering: flexible but vulnerable
- Every exception weakens security
- Need change management process

### Where to start

```bash
# Understand protocol implementations
ls components/protocols/

# Look at Modbus function codes
grep -r "function_code\|FC_\|WRITE\|READ" components/protocols/modbus*

# Find S7 connection handling
grep -r "def connect\|def read\|def write" components/protocols/s7*

# Find where to add filtering
grep -r "def handle_request\|def process_" components/protocols/
```

### Going deeper

**Questions to explore:**
- How do you handle legitimate exceptions (vendor access, emergency operations)?
- What's the change management process for firewall rules?
- How do you test rules without breaking production?
- How do you handle protocols that don't support authentication?

**Advanced options:**
- Implement stateful protocol inspection
- Deploy protocol-aware firewall
- Implement rate limiting per connection
- Create protocol anomaly detection (unexpected sequences)
- Deploy application-layer gateway
- Implement protocol normalization

## Challenge 6: Session management and dual authorization

**The problem:** Some operations are too critical for one person. Safety bypasses, reactor shutdowns, emergency procedures need two-person rule.

**Your goal:** Implement dual authorization for safety-critical operations.

### What you'll do

**Identify critical operations:**
- Reactor shutdown
- Safety system bypass
- Emergency turbine stop
- Force operations (overriding sensors)

**Implement dual authorization:**
```python
from components.security.authentication import AuthenticationManager

auth = AuthenticationManager()

# Requires two separate authenticated sessions
if await auth.authorize_with_dual_auth(
    session_id_1,  # First person
    session_id_2,  # Second person
    PermissionType.SAFETY_BYPASS,
    "reactor_1"
):
    # Both authorized, proceed with operation
    await reactor.bypass_safety_interlock()
```

**Configure session management:**
- Set session timeouts (`simulation.yml`)
- Handle timeout during long operations
- Implement session refresh
- Handle logout

**Handle edge cases:**
- What if only one supervisor is on duty?
- What about genuine emergencies?
- How do you prevent colluding insiders?

### Test it

**Authorization testing:**
```bash
# Try critical operation with single auth - should fail
# Try with two operators - should fail (insufficient privileges)
# Try with two supervisors - should succeed
# Try with same user twice - should fail
```

**Session testing:**
- Start operation, wait for session timeout, try to complete
- Logout one user mid-operation
- Simulate network failure affecting one session

**Usability testing:**
- How long does dual auth take?
- Is it practical during emergencies?
- Do operators work around it?

**Collusion testing:**
- Can two insiders collude?
- What controls prevent abuse?
- How do you detect suspicious patterns?

### What you'll learn

**Two-person rule:**
- Simple concept, complex implementation
- How do you verify two different people?
- What if they're physically next to each other?
- Technical control vs procedural control

**Security vs emergency response:**
- Dual auth delays emergency actions
- But prevents unauthorized actions
- Need emergency override procedures
- But override can be abused
- No perfect solution

**Session management complexity:**
- Long-running operations and timeouts
- Refresh vs re-authenticate
- Graceful degradation when session expires
- User experience of authentication

**Detection over prevention:**
- Can't always prevent authorized users from abusing privileges
- Need logging and monitoring for detection
- Need regular audit of dual-auth operations
- Look for patterns (same pairs always working together)

### Where to start

```bash
# Look at dual authorization
grep -A 30 "authorize_with_dual_auth" components/security/authentication.py

# Find safety-critical operations
grep -r "safety\|emergency\|shutdown\|bypass" components/devices/ | grep "def "

# Check session configuration
grep -r "session_timeout" simulation.yml components/

# Look at permission types for critical operations
grep "class PermissionType" components/security/authentication.py
```

### Going deeper

**Questions to explore:**
- How do you handle shift changes during long operations?
- What's the audit process for dual-auth operations?
- How do you detect patterns of collusion?
- How do you balance security and operational needs?

**Advanced options:**
- Implement three-person rule for most critical operations
- Deploy time-delayed authorization (wait period between approvals)
- Implement role separation (engineer + supervisor, not two engineers)
- Create approval workflows with justification requirements
- Deploy biometric authentication (ensure physical presence)
- Implement video recording of critical operations
- Deploy behaviour analytics to detect insider threats

## Combining detection challenges

Implement all three together for comprehensive detection:

**Layered detection:**
1. **Anomaly detection** - catches unusual behaviour
2. **Protocol filtering** - blocks dangerous operations at protocol level
3. **Dual authorization** - prevents insider abuse of critical functions

**Test the combination:**
- Run an attack - which layers detect it?
- Which layers block it?
- What gets through all three?
- Where are the gaps?

**Build a detection matrix:**
```
Attack Type          | Anomaly | Protocol | Dual Auth | Result
---------------------|---------|----------|-----------|--------
External Overspeed   | Yes     | Yes      | N/A       | Blocked
Insider Overspeed    | Yes     | No       | N/A       | Detected
Authorized Bypass    | Maybe   | No       | Yes       | Prevented
Gradual Attack       | Maybe   | No       | N/A       | Risky
Reconnaissance       | No      | No       | N/A       | Undetected
```

Where are your blind spots?

---

*"You can't prevent everything. But you can detect most things. The question is whether you're watching." - Ponder Stibbons*
