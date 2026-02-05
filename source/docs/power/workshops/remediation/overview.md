# Remediation challenges

*You broke it. Now fix it.*

## What this is

You've spent time exploring vulnerabilities in UU Power & Light. You found unauthenticated protocols, missing access controls, and systems that trust anyone who asks nicely. Now comes the harder part: securing them without breaking everything.

These challenges use the security components in `components/security/`. They involve modifying configuration and code to add security controls, then testing whether they work - and what they break.

## Before you start

**Read the security components documentation:**
```bash
cat components/security/README.md
```

This explains the authentication, encryption, logging, and anomaly detection systems available to you.

**Important:** The simulator starts vulnerable by design. Your job is to secure it.

## How to use these challenges

**Pick any challenge.** They're loosely organised by difficulty, but you can start anywhere.

**Implement the security control.** Use the components provided, modify configurations, integrate authentication where none exists.

**Test it.** Run your attack scripts from earlier. Do they still work? Can legitimate operators still do their jobs?

**Learn from what breaks.** Every security control has trade-offs. Discover them by doing.

**No right answers.** Every implementation has costs and benefits. Your job is to understand them.

## Challenge categories

### Configuration and authentication

Start here if you're new to OT security or want quick wins:

1. **Password protect the SCADA** - Enable OPC UA authentication
2. **Implement RBAC** - Create roles and enforce permissions
3. **Deploy logging and auditing** - Capture security-relevant events

These are "easy" in that the components exist. They're hard because you'll discover what breaks when you add authentication.

### Detection and monitoring

Build visibility and detection capabilities:

4. **Anomaly detection deployment** - Detect abnormal turbine behaviour
5. **Protocol-level filtering** - Restrict dangerous Modbus and S7 operations
6. **Session management and dual authorization** - Implement two-person rule

These teach you about false positives, alarm fatigue, and security-usability trade-offs.

### Architecture and encryption

Fundamental changes to how the system operates:

7. **Encrypt SCADA communications** - Deploy OPC UA signing and encryption
8. **Implement jump host architecture** - Centralise administrative access
9. **Network segmentation (IEC 62443 zones)** - Zone-based architecture

These are the most complex. They require architectural thinking and have significant operational impact.

### Your own architecture

Apply everything you've learned:

10. **Build a complete security architecture** - Fix your top 3-5 findings comprehensively
11. **Design and defend a critical operation** - Secure one operation end-to-end

These are open-ended. Design, implement, test, document trade-offs.

## What you'll learn

**Technical skills:**
- Implementing authentication and authorisation
- Certificate management and encryption
- Anomaly detection and monitoring
- Network segmentation and architecture

**Contextual understanding:**
- Why "just add a password" is complicated
- Security vs usability trade-offs
- What breaks when you secure things
- Emergency procedures and break-glass access
- Operational constraints on security controls

**Most importantly:**
You'll understand that finding vulnerabilities is the easy part. Getting them fixed while maintaining operations, staying within budget, and keeping systems usable - that's where security work actually happens.

## Tips for success

**Start small.** Pick one challenge, implement it, test it thoroughly before moving on.

**Test thoroughly.** Run your old attack scripts. Try to bypass your own controls. Simulate normal operations.

**Document what breaks.** Every control has costs. Write down what stops working, what gets harder, what becomes impossible.

**Ask "what if?"** What if authentication fails during emergency? What if certificates expire? What if the jump host crashes?

**Compare notes.** Different people will make different trade-offs. Discuss why.

## After you're done

Reflect on:
- What was harder than expected?
- What trade-offs did you encounter?
- What would you prioritise if budget/time were limited?
- What's fundamentally unfixable without major changes?

Share your findings. Compare implementations. Discuss trade-offs.

Understanding remediation is understanding real security work.

---

*"It's not what you find. It's what you do about what you find." - Ponder Stibbons*
