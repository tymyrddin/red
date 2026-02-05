# Student Guide: The UU Power & Light Security Roleplay

*How to spend a day learning pentesting by playing roles and hacking things*

## The Story

Unseen University Power & Light supplies electricity to the University, the Patrician's Palace, and half of Ankh-Morpork. The Archchancellor is worried about security after reading about ransomware in the Times. He's hired a red team (that's some of you) to "check if we're secure" and the University security team (more of you) to "make sure we are."

Operations (even more of you) just wants to keep the turbines spinning. And Lord Vetinari wants to know if this is actually important or just expensive consultants being alarmist.

You'll play through a full day discovering vulnerabilities, arguing about what to fix, and trying to convince skeptical stakeholders to care.

## Choose Your Role

### Red Team: The Hackers (4-5 people)

**Your job:** Break everything. Find vulnerabilities. Create spectacular proof of concepts. Scare the executives.

**What you'll do:**
- Hack into PLCs, SCADA servers, and control systems
- Prove you can shut down turbines remotely
- Steal control logic and operational data
- Write a scary report with evidence
- Present findings to increasingly skeptical audiences

**Skills you'll learn:**
- Industrial protocol pentesting
- Network reconnaissance
- Exploitation and proof of concepts
- Security report writing
- Stakeholder presentations

**Why it's fun:** You get to be the attacker. Break stuff. Watch things crash. Say "I told you so."

### Blue Team: The Defenders (2-3 people)

**Your job:** Understand current security. Help prioritize fixes. Work with operations to implement solutions.

**What you'll do:**
- Document existing security controls (spoiler: there aren't many)
- Review red team findings and assess them
- Figure out what's actually fixable
- Develop remediation plans
- Support presentations and defend recommendations

**Skills you'll learn:**
- Defensive security thinking
- Remediation planning
- Working with operations constraints
- Balancing security and functionality
- Negotiation and compromise

**Why it's fun:** You're the reasonable middle ground. Red team wants to shut everything down. Operations wants to change nothing. You find solutions.

### Operations: The Realists (2-3 people)

**Your job:** Keep the power running. Push back on changes that risk disruption. Be appropriately skeptical of "security experts."

**What you'll do:**
- Document operational constraints (maintenance windows, downtime costs)
- Challenge red team findings ("Can they really do that?")
- Push back on impractical recommendations
- Negotiate realistic timelines
- Protect your turbines from well-meaning security people

**Skills you'll learn:**
- Understanding operational perspective
- Risk assessment in context
- Stakeholder negotiation
- Defending decisions under pressure
- Finding practical compromises

**Why it's fun:** You get to say no to the security people. Your systems work fine. Why are these consultants trying to break them?

### University Leadership (2-3 people)

**Your job:** Control the budget. Ask hard questions. Approve or reject recommendations based on strategic value.

**Roles:** Archchancellor (doesn't understand tech), Bursar (controls money), Safety Officer (cares about safety)

**What you'll do:**
- Question every cost estimate
- Ask "have we been attacked? No? Then why is this urgent?"
- Make red team explain things in language you understand
- Decide what gets funded and what doesn't
- Represent University interests to the Patrician

**Skills you'll learn:**
- Executive decision-making
- Translating technical to business language
- Budget prioritization
- Asking probing questions
- Strategic thinking

**Why it's fun:** You have the power. Red team found vulnerabilities? So what? Convince you it matters and you'll approve funding. Otherwise, no.

### The Patrician (1 person - facilitator or experienced student)

**Your job:** Represent city interests. Ask the really hard questions. Make final decisions.

**What you'll do:**
- Observe presentations
- Ask strategic questions that reveal flawed thinking
- Test whether recommendations make sense for Ankh-Morpork
- Approve, reject, or modify final recommendations
- Be Vetinari (analytical, patient, strategic, slightly terrifying)

**Skills you'll learn:**
- Strategic analysis
- Socratic questioning
- Decision-making under uncertainty
- Separating signal from noise
- Leadership in ambiguous situations

**Why it's fun:** You're the final boss. Everyone wants your approval. You decide who makes sense and who doesn't.

## The Day's Flow (Flexible!)

### Morning: Discovery

**Red team:** Hack everything. Find vulnerabilities. Create proof of concepts. Document what you find.

Use the simulator and scripts:
```bash
# Reconnaissance
python scripts/recon/raw-tcp-probing.py
python scripts/recon/turbine_recon.py

# Exploitation
python scripts/exploitation/turbine_overspeed_attack.py
python scripts/exploitation/turbine_emergency_stop.py
python scripts/vulns/s7_readonly_block_dump.py
```

**Blue team + Operations:** Document current state. Understand the facility. Prepare context for red team findings.

**Leadership:** Prepare questions. Understand budget constraints. Think about priorities.

**Pace:** Self-directed. If red team is having fun hacking, let them hack. If they're stuck, help them. No rigid schedule.

### Midday: Sharing Findings

**Everyone together:** Red team presents what they found. Technical discussion. Blue team and operations provide context. Leadership asks questions.

This is collaborative, not adversarial. Red team explains attacks. Blue team thinks about fixes. Operations identifies constraints.

### Afternoon: Remediation and Decisions

**All teams work together** (except leadership who prepares to evaluate):

- Prioritize findings: What's most important to fix?
- Develop remediation plans: What's actually feasible?
- Estimate costs and timelines: What's realistic?
- Create three-tier roadmap: Quick wins, medium-term, strategic initiatives

Use the prioritization framework from **masterclass2-remediation.md** but don't be rigid. Argue. Negotiate. Find compromises.

### Late Afternoon: The Gauntlet

**Present to stakeholders:**

1. **Technical briefing:** Red team → Blue team + Operations (friendly, detailed, technical)

2. **Executive briefing:** Red team + Blue team → University Leadership (business language, visual demos, cost justification)

3. **Patrician briefing:** Everyone → Vetinari (strategic, city-level, final judgment)

**Then negotiate:** Based on feedback, adjust recommendations. Get final approval. Decide what actually gets implemented.

## Tips for Success

### For Red Team

**Do:**
- Create visual proof of concepts (videos of turbines crashing)
- Document everything with evidence
- Think about business impact, not just technical severity
- Practice explaining attacks in simple language

**Don't:**
- Just list findings without context
- Use jargon without explaining it
- Ignore operational constraints
- Get defensive when questioned

**Pro tip:** The turbine emergency stop is spectacular. Always demo that one.

### For Blue Team

**Do:**
- Challenge red team findings constructively
- Think creatively about solutions
- Work with operations, not against them
- Find compromises that improve security without breaking operations

**Don't:**
- Just agree with red team
- Ignore operational realities
- Propose fixes without cost/timeline estimates
- Side with one team against another

**Pro tip:** You're the bridge between security and operations. Be the reasonable voice.

### For Operations

**Do:**
- Push back on impractical recommendations (that's your job!)
- Provide real constraints (downtime costs, maintenance windows)
- Propose operational alternatives to security recommendations
- Defend your systems while staying open to improvements

**Don't:**
- Say "no" to everything (be realistic, not obstructionist)
- Get personally defensive (it's roleplay!)
- Ignore actual security risks
- Refuse to engage

**Pro tip:** "That requires 32 hours of downtime and we have one 4-day maintenance window per year" is a legitimate constraint. Use it.

### For Leadership

**Do:**
- Ask questions until you understand
- Question costs and timelines
- Make red team translate technical to business language
- Consider University priorities beyond just security

**Don't:**
- Pretend to understand technical details you don't
- Approve everything automatically
- Ignore budget constraints
- Be unnecessarily hostile

**Pro tip:** "Have we been attacked? No? Then explain why this is urgent" is a powerful question.

### For the Patrician

**Do:**
- Listen carefully before speaking
- Ask one precise question that cuts to the core issue
- Test strategic thinking, not technical knowledge
- Be fair but challenging

**Don't:**
- Dominate the conversation
- Ask gotcha questions with no good answer
- Be hostile or dismissive
- Override everything (sometimes teams make good arguments)

**Pro tip:** See **masterclass-red-team-patrician.md** for detailed guidance on playing this role.

## Learning Resources

### Before you start
- Read the UU P&L simulator README
- Review industrial protocol basics (if new to OT)
- Browse attack scripts to see what's possible

### During the day
- **masterclass2-remediation.md:** Detailed guide on prioritization, reporting, and fixes
- **masterclass-red-team-scenario.md:** Attack scenarios and techniques
- Script documentation in the simulator repository

### After the day
- Keep the simulator for practice
- Review your report and improve it
- Try different roles next time
- Practice stakeholder communication

## Common Questions

**Q: I've never done OT security. Will I be lost?**
A: No! Scripts are provided. Facilitators will help. You'll learn by doing.

**Q: What if my team finishes early?**
A: Go deeper. Find more attacks. Create better proof of concepts. Practice presentations.

**Q: What if we're stuck?**
A: Ask facilitators for hints. Collaborate with other teams. Try different approaches.

**Q: Do we have to follow the schedule exactly?**
A: No! It's flexible. Learn at your own pace. Have fun with it.

**Q: What if our roles conflict?**
A: That's the point! Red team vs Operations tension is realistic. Work through it.

**Q: Can we switch roles during the day?**
A: Usually no - stay in character. But for future workshops, definitely try different roles!

**Q: What if the Patrician rejects our recommendations?**
A: Learn from it. What did you miss? What could you have argued better? That's the learning.

## What Makes This Educational

You're not learning from lectures. You're learning from:
- **Experience:** Actually performing pentesting, not watching demos
- **Mistakes:** Getting stakeholder questions wrong, then figuring out better answers
- **Perspective:** Seeing problems from multiple viewpoints (attacker, defender, operations, executive)
- **Negotiation:** Finding solutions when people disagree
- **Reality:** Understanding that technical correctness doesn't automatically win arguments

The best learning happens when:
- You're explaining an attack and realize the stakeholder doesn't understand
- Operations points out a flaw in your recommendation you hadn't considered
- The Patrician asks a question you can't answer
- You find a compromise that satisfies both security and operations
- You present evidence that actually convinces skeptical executives

## Success Looks Like

By end of day, you should:
- Understand industrial protocol security (or lack thereof)
- Know how to perform OT pentesting reconnaissance and exploitation
- Be able to write a security assessment report with evidence
- Understand how to prioritize remediation considering multiple factors
- Know how to present technical findings to non-technical audiences
- Recognize that security is about people and communication, not just technology
- Want to practice more because you discovered this is harder and more interesting than expected

## Most Important Rule

**Have fun!**

This is serious learning through playful experience. Yes, you're developing professional skills. But you're doing it by being hackers, defenders, and bureaucrats in a Discworld power plant.

Take the learning seriously. Don't take yourself too seriously.

Break things. Fix things. Argue about things. Learn things.

Welcome to Ankh-Morpork. Your adventure begins now.

---

*"Getting an education was a bit like a communicable sexual disease. It made you unsuitable for a lot of jobs and then you had the urge to pass it on." - Terry Pratchett*

*Today you get infected with OT security knowledge. Tomorrow you'll want to hack all the industrial control systems. We apologize in advance.*
