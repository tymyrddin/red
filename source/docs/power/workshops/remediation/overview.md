# Overview

![SCADA](/_static/images/ot-scada.png)

<p style="text-align: center;"><em>You broke it. Now fix it.</em></p>

## What this is

You have spent time [exploring vulnerabilities in UU Power & Light](../attack-masterclass/index.rst). You found 
unauthenticated protocols, missing access controls, and systems that trust anyone who asks nicely. Now comes the 
harder part: securing them without breaking everything.

These challenges use the security components in `components/security/`. They involve modifying configuration and 
code to add security controls, then testing whether they work, and what they break.

## Getting started

### Setup

[Have it installed on your machine](https://github.com/ninabarzh/power-and-light-sim), or install it at another 
machine (and then adapt the IP adresses in the hacking scripts)

Start the simulator:
```bash
python tools/simulator_manager.py
```

Test that it's working in a separate terminal or other machine:
```bash
python scripts/recon/raw-tcp-probing.py
```

You should see ports listening: 102, 103, 4840, 4841, 10501-10504, 44818-44820.

## Before you start

Read the security components documentation:
```bash
cat components/security/README.md
```

This explains the authentication, encryption, logging, and anomaly detection systems available to you.

Important: The simulator starts vulnerable by design. Your job is to secure it.

## How to use these challenges

- Pick any challenge. They're loosely organised by difficulty, but you can start anywhere.
- Implement the security control. Use the components provided, modify configurations, integrate authentication where none exists.
- Test it. Run your attack scripts from earlier. Do they still work? Can legitimate operators still do their jobs?
- Learn from what breaks. Every security control has trade-offs. Discover them by doing.
- No right answers. Every implementation has costs and benefits. Your job is to understand them.

## Challenge categories

### Configuration and authentication

Start here if you're new to OT security or want quick wins:

1. [Password protect the SCADA](1.md): Enable OPC UA authentication
2. [Implement RBAC](2.md): Create roles and enforce permissions
3. [Deploy logging and auditing](3.md): Capture security-relevant events

These are "easy" in that the components exist. They're hard because you'll discover what breaks when you add authentication.

### Detection and monitoring

Build visibility and detection capabilities:

4. [Anomaly detection deployment](4.md): Detect abnormal turbine behaviour
5. [Protocol-level filtering](5.md): Restrict dangerous Modbus and S7 operations
6. [Session management and dual authorisation](6.md): Implement two-person rule

These teach you about false positives, alarm fatigue, and security-usability trade-offs.

### Architecture and encryption

Fundamental changes to how the system operates:

7. [Encrypt SCADA communications](7.md): Deploy OPC UA signing and encryption
8. [Implement jump host architecture](8.md): Centralise administrative access
9. [Network segmentation (IEC 62443 zones)](9.md): Zone-based architecture

These are the most complex. They require architectural thinking and have significant operational impact.

### Your own architecture

Apply everything you've learned:

10. [Build a complete security architecture](10.md): Fix your top 3-5 findings comprehensively
11. [Design and defend a critical operation](11.md): Secure one operation end-to-end
12. [Combine challenge 10 and 11](12.md): The challenge

These are open-ended. Design, implement, test, document trade-offs.

## What you can learn

Technical skills:
- Implementing authentication and authorisation
- Certificate management and encryption
- Anomaly detection and monitoring
- Network segmentation and architecture

Contextual understanding:
- Why "just add a password" is complicated
- Security vs usability trade-offs
- What breaks when you secure things
- Emergency procedures and break-glass access
- Operational constraints on security controls

Finding vulnerabilities is the easy part. Getting them fixed while maintaining operations, staying within budget, and 
keeping systems usable, is the harder part.

## Tips

Start small. Pick one challenge, implement it, test it thoroughly before moving on.

Test thoroughly. Run your old attack scripts. Try to bypass your own controls. Simulate normal operations.

Document what breaks. Every control has costs. Write down what stops working, what gets harder, what becomes impossible.

Ask "what if?" What if authentication fails during emergency? What if certificates expire? What if the jump host crashes?

Compare notes. Different people will make different trade-offs. Discuss why.

## Retrospection

Reflect on:
- What was harder than expected?
- What trade-offs did you encounter?
- What would you prioritise if budget/time were limited?
- What's fundamentally unfixable without major changes?

Share your findings. Compare implementations. Discuss trade-offs.

---

*"It's not what you find. It's what you do about what you find." ~ Ponder Stibbons*
