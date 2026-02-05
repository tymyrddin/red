# Your own architecture

*Apply everything you've learned*

## Overview

These aren't prescriptive challenges with specific steps. These are open-ended design challenges where you apply everything you've learned to build comprehensive security architectures.

No hand-holding. No specific instructions. Just the goal and your judgement.

## Challenge 10: Build a complete security architecture

**The challenge:** You conducted a pentest. You found 10-15 vulnerabilities. Pick your top 3-5 critical findings. Implement comprehensive remediations addressing all of them.

### Your approach

**Prioritise findings:**
- Which findings matter most?
- Safety impact?
- Operational impact?
- Likelihood of exploitation?
- Business impact?

Use a prioritisation framework:
```
Priority = (Safety × 2) + (Operational × 1.5) + (Likelihood × 1.5) + (Business × 1) / Remediation Feasibility
```

**Choose 3-5 critical findings:**
Don't try to fix everything. Focus on what matters most.

Examples:
- Unauthenticated Modbus access to turbines
- Anonymous SCADA access
- No network segmentation
- Missing safety system isolation
- Lack of audit logging

**Design comprehensive remediations:**
For each finding, design complete fix:
- Technical controls (what to implement)
- Process controls (procedures, change management)
- Monitoring and detection (how to know if it's working)
- Incident response (what to do when it fails)

**Implement defense in depth:**
Don't rely on single control. Layer defenses:
- Authentication (who are you?)
- Authorization (what can you do?)
- Network segmentation (limit blast radius)
- Monitoring (detect attacks)
- Logging (forensics and audit)

**Document trade-offs:**
Every remediation has costs. Document:
- Implementation cost (time, money, effort)
- Operational impact (what becomes harder?)
- Performance impact
- Maintenance burden
- Limitations (what doesn't this fix?)
- Residual risk (what's still vulnerable?)

### Test comprehensively

**Security testing:**
- Run your original attack scripts
- Do they still work?
- Can you find new bypasses?
- Test each layer independently

**Operational testing:**
- Can operators do their jobs?
- What workflows changed?
- What's harder now?
- What's impossible now?

**Failure scenario testing:**
- What happens when controls fail?
- Authentication server down?
- Firewall misconfigured?
- Certificates expired?
- Can operations continue?

**Red team vs blue team:**
If you have others working on this:
- Swap simulators
- Try to break each other's defenses
- Learn from what works
- Learn from what fails

### What you'll learn

**Prioritisation is hard:**
- Can't fix everything
- Resources are limited
- Some things are unfixable
- Risk acceptance is reality

**Defense in depth works:**
- No single control is sufficient
- Multiple layers catch what one misses
- But complexity increases
- More maintenance burden

**Trade-offs are everywhere:**
- Security vs usability
- Security vs operational flexibility
- Security vs performance
- Security vs cost
- Every choice is a trade-off

**Documentation matters:**
- Why did you choose these remediations?
- What trade-offs did you accept?
- What residual risks remain?
- Future you will need this information

**Perfection is impossible:**
- There's always residual risk
- Accept it, document it, monitor it
- Focus on what matters most

### Where to start

```bash
# Review your pentest findings
# List all vulnerabilities found

# For each vulnerability, assess:
# - Safety impact (1-5)
# - Operational impact (1-5)
# - Likelihood (1-5)
# - Business impact (1-5)
# - Remediation feasibility (1-5)

# Calculate priority scores
# Choose top 3-5

# For each chosen finding:
# - Design remediation (what controls?)
# - Estimate cost (time, money, effort)
# - Document trade-offs
# - Implement
# - Test
# - Document results
```

### Example approach

**Finding 1: Unauthenticated Modbus to turbines**

Remediations:
- Technical: IP whitelisting at firewall (only SCADA and engineering)
- Technical: Deploy anomaly detection for abnormal Modbus traffic
- Technical: Integrate logging for all Modbus writes
- Process: Change management for firewall rules
- Monitoring: Alert on Modbus connections from non-whitelisted IPs
- Incident response: Procedure for investigating unauthorized access attempts

Trade-offs:
- Cost: 16 hours implementation, minimal financial cost
- Operational impact: Vendor remote access requires firewall change
- Performance: None (firewall rules are fast)
- Maintenance: Need to update whitelist when systems change
- Limitations: Doesn't authenticate, just restricts source IPs (can be spoofed on local network)
- Residual risk: Insider or compromised HMI still has full access

Test:
- From unauthorized IP: Access blocked ✓
- From SCADA: Access works ✓
- From compromised HMI: Still works (residual risk) ✗
- Anomaly detection catches unusual writes ✓

**Finding 2: Anonymous SCADA access**

Remediations:
- Technical: Enable OPC UA authentication (see Challenge 1)
- Technical: Generate and deploy certificates
- Technical: Integrate authorization checks
- Process: Certificate lifecycle management procedures
- Monitoring: Log all authentication attempts
- Incident response: Procedure for handling compromised certificates

Trade-offs:
- Cost: 40 hours implementation, €5,000 for certificate management
- Operational impact: All clients need certificates, HMI reconfiguration
- Performance: ~10ms latency increase per connection
- Maintenance: Certificate renewal every year
- Limitations: Doesn't encrypt data, just authenticates (see Challenge 7 for encryption)
- Residual risk: Compromised client certificate still grants access

Continue this for each priority finding...

## Challenge 11: Design and defend a critical operation

**The challenge:** Choose one critical operation. Implement complete security controls for that one operation end-to-end. Make it both secure and usable.

### Choose your operation

Pick one:

**Option 1: Reactor startup**
- Complex multi-step procedure
- Safety-critical
- Requires coordination between multiple systems
- Takes 30-60 minutes
- Errors can be dangerous

**Option 2: Turbine emergency stop**
- Must be fast (seconds matter)
- Safety-critical
- Can't have delays
- But must prevent unauthorized stops
- Balance security and speed

**Option 3: Safety system bypass**
- Extremely dangerous if abused
- Legitimate need during maintenance
- Must be temporary and monitored
- Require multiple approvals
- Automatic revert

### Design comprehensive controls

**Pre-operation:**
- Who can initiate?
- What permissions required?
- Any approvals needed?
- Preconditions (system state checks)?

**Authentication:**
- Single person or dual authorization?
- What role is required?
- Certificate-based? Password? MFA?

**Authorization:**
- What permissions grant access?
- Time-based (only during maintenance windows)?
- Location-based (only from control room)?

**Initiation:**
- How is operation triggered?
- Any confirmation required?
- Any wait period (cooling-off)?

**During operation:**
- Monitoring and logging
- Progress tracking
- Anomaly detection
- Ability to abort?
- Who can abort?

**Safety interlocks:**
- What safety checks during operation?
- Automatic abort conditions?
- Override procedures?

**Completion:**
- Success criteria
- Validation checks
- Automatic revert (for bypass operations)
- Notification

**Post-operation:**
- Logging and audit trail
- Who did what when?
- Success or failure?
- Any anomalies detected?

**Emergency scenarios:**
- What if authentication fails?
- What if safety interlock triggers?
- What if operation hangs?
- Break-glass procedures?

### Implement and test

**Normal operation testing:**
- Authorized user performs operation
- Everything works smoothly
- Logging captures all steps
- Operation completes successfully

**Authorization testing:**
- Unauthorized user attempts operation - blocked
- Wrong role attempts operation - blocked
- Dual auth with only one person - blocked

**Safety testing:**
- Trigger safety interlock during operation
- Operation should abort safely
- System returns to safe state

**Failure testing:**
- Authentication server down during operation
- What happens?
- Can operation proceed?
- Can operation complete?

**Emergency testing:**
- Real emergency requiring immediate action
- Can you bypass procedures?
- Is it audited?
- Can you justify it later?

**Usability testing:**
- How long does the secure operation take vs unsecured?
- Is the delay acceptable?
- Do operators find it reasonable?
- Or will they work around it?

### What you'll learn

**Security vs safety:**
- Sometimes they conflict
- Security can delay safety responses
- Need emergency overrides
- But overrides can be abused
- No perfect answer

**Usability vs security:**
- Most secure: lock it down completely
- Most usable: no controls
- Reality: somewhere in between
- Finding balance requires iteration

**Operational realities:**
- Procedures look good on paper
- Reality is messier
- Emergencies don't follow procedures
- Edge cases multiply
- Need flexibility

**Defense in depth for operations:**
- Authentication (who)
- Authorization (permission)
- Dual authorization (two-person rule)
- Safety interlocks (prevent physical danger)
- Monitoring (detect anomalies)
- Logging (audit trail)
- Emergency procedures (break-glass)

### Where to start

```bash
# Choose your operation
# (Recommend reactor startup or safety bypass)

# Map the operation:
# 1. What are the steps?
# 2. What systems are involved?
# 3. What can go wrong?
# 4. What are the risks?

# Design security controls:
# For each phase (pre, during, post):
# - What checks?
# - What approvals?
# - What monitoring?
# - What logging?

# Consider emergency scenarios:
# - Authentication failure
# - Safety interlock triggers
# - Operation hangs
# - Real emergency requiring immediate action

# Implement incrementally:
# - Start with authentication
# - Add authorization
# - Add dual auth if needed
# - Add monitoring
# - Add logging
# - Test each addition

# Test thoroughly:
# - Normal operation
# - Unauthorized attempts
# - Failure scenarios
# - Emergency scenarios
# - Usability (is it practical?)
```

### Example: Safety system bypass

**Chosen operation:** Bypass reactor safety interlock during maintenance

**Why it's critical:**
- Allows maintenance while reactor is hot
- Removes safety protection
- Dangerous if abused or forgotten
- Must be temporary and monitored

**Pre-operation controls:**
- Dual authorization required (supervisor + engineer)
- Justification required (text field: why are you bypassing?)
- Maintenance window validation (only allowed during scheduled maintenance)
- Safety system status check (ensure other interlocks still active)
- Automatic expiry configured (1 hour default, max 4 hours)

**During operation controls:**
- Alarm displayed on all HMIs: "SAFETY BYPASS ACTIVE"
- Monitoring for any safety parameter violations
- Logging all operations performed during bypass
- Ability to abort maintenance and restore safety
- Countdown timer showing time until automatic revert

**Post-operation controls:**
- Automatic revert after time limit
- Manual restore option (before time limit)
- Validation that safety system restored
- Test that safety interlock is functional
- Audit log entry with: who, when, duration, justification, what was done
- Report to safety officer

**Emergency procedures:**
- If safety parameter exceeds threshold during bypass, automatic revert
- If reactor enters unsafe state, forced shutdown
- Emergency button overrides bypass immediately

**Implementation:**
```python
# Simplified pseudocode
async def request_safety_bypass(user1_session, user2_session, justification, duration_minutes):
    # Dual authorization check
    if not await auth.authorize_with_dual_auth(
        user1_session, user2_session,
        PermissionType.SAFETY_BYPASS, "reactor_1"
    ):
        log_security("Safety bypass denied - insufficient authorization")
        return False

    # Maintenance window check
    if not in_maintenance_window():
        log_security("Safety bypass denied - not in maintenance window")
        return False

    # Duration limit check
    if duration_minutes > 240:  # Max 4 hours
        log_security("Safety bypass denied - duration exceeds maximum")
        return False

    # Record justification
    await log_audit(
        "Safety bypass requested",
        user1=get_user(user1_session),
        user2=get_user(user2_session),
        justification=justification,
        duration=duration_minutes
    )

    # Activate bypass
    await reactor.bypass_safety_interlock("temperature_high", duration_minutes)

    # Start monitoring
    await start_bypass_monitoring("reactor_1", duration_minutes)

    # Display alarm on all HMIs
    await hmi.show_alarm("SAFETY BYPASS ACTIVE", AlarmPriority.HIGH)

    return True
```

**Testing results:**
- ✓ Dual auth required (single user attempt blocked)
- ✓ Justification required (empty justification rejected)
- ✓ Maintenance window enforced (attempt during production blocked)
- ✓ Duration limited (5-hour request rejected)
- ✓ Automatic revert after time limit
- ✓ Emergency revert on safety parameter violation
- ✓ Complete audit trail

**Trade-offs accepted:**
- Adds ~2 minutes to bypass procedure (dual auth, justification)
- Acceptable for maintenance operations (not emergencies)
- Manual restore required after maintenance (can't auto-detect "maintenance complete")
- False alarms possible (parameter violations during normal maintenance)

**Residual risks:**
- Two colluding insiders can still abuse bypass
- Mitigation: Audit review, pattern detection
- Operator fatigue could lead to expired bypass not being noticed
- Mitigation: Countdown timer, alarm, automatic revert

## Combining challenges 10 and 11

For the ultimate challenge:

1. Build complete security architecture (Challenge 10)
2. Design secure critical operation (Challenge 11)
3. Integrate them: your critical operation uses your security architecture
4. Test: Does it work? Is it secure? Is it usable?

This is what real OT security programs do.

---

*"Security isn't a feature you add. It's an architecture you build. And it's never finished." - Ponder Stibbons*
