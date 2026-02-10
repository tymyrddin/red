# Facilitator guide

*How to run the around 3-hour OT pentesting masterclass*

## Pre-workshop preparation

### Technical setup (1 week before)

Verify simulator installation:
```bash
git clone https://github.com/ninabarzh/power-and-light-sim.git
cd power-and-light-sim
pip install -r requirements.txt
python -m src.main
```

Test all scripts participants will use:
- Reconnaissance scripts (raw-tcp-probing, modbus_identity_probe, turbine_recon)
- Vulnerability assessment scripts (modbus_coil_register_snapshot, s7_plc_status_dump, opcua_readonly_probe)
- Exploitation scripts (turbine_overspeed_attack, turbine_emergency_stop, historian_exfiltration)

Prepare backup materials:
- Pre-recorded attack videos in case scripts fail
- Screenshots of expected outputs
- Sample reports and presentations

Environment options:
- Option 1: Each team runs simulator locally (best for learning)
- Option 2: Shared simulator instance (better for limited resources)
- Option 3: Cloud-hosted instances (best for remote delivery)

### Participant communication (1 week before)

Send installation instructions:
```
Please install the UU P&L simulator before the workshop:

git clone https://github.com/ninabarzh/power-and-light-sim.git
cd power-and-light-sim
pip install -r requirements.txt
python -m src.main

If you encounter installation issues, arrive 15 minutes early for technical support.
```

Send pre-reading (optional):
- Overview of OT security challenges
- Industrial protocol basics
- UU P&L facility description

### Physical/virtual setup (day of workshop)

In-person requirements:
- Room for 4-6 teams to work independently
- Projector for presentations
- Whiteboard or flip charts
- Team workspaces with power/network
- Timer visible to all participants
- Separate space for stakeholder briefing presentations

Remote requirements:
- Video conferencing platform with breakout rooms
- Shared document for findings (Google Docs, Notion, etc.)
- Screen sharing capability
- Virtual whiteboard (Miro, Mural, etc.)
- Slack or chat for coordination

### Materials checklist

- [ ] Team assignment cards
- [ ] Stakeholder persona cards
- [ ] Timing schedule printed/displayed
- [ ] Scoring rubric
- [ ] Sample report templates
- [ ] Stakeholder question bank
- [ ] Patrician question cards (special set)
- [ ] Prizes for winning team (optional but fun)

## Workshop facilitation guide

### Opening (~10 minutes)

Welcome and context, something like:

*Welcome to the UU Power & Light red team assessment roleplay. Today you can experience the full cycle of OT 
pentesting: technical assessment, proof of concept development, and the hard part: convincing sceptical stakeholders 
to act on your findings.*

*You are red teams hired to assess UU P&L from a nation-state threat actor perspective. Your client: Unseen University. 
Your ultimate stakeholder: [Lord Vetinari, Patrician of Ankh-Morpork](https://indigo.tymyrddin.dev/docs/vetinari/).*

*The technical work is Phase 1. The stakeholder presentation is Phase 2. Many participants expect Phase 1 to be harder. 
They're wrong.*

Team formation:
- 3-4 people per team (no more than 6 teams total)
- Mix experience levels within teams
- Assign roles: Lead Pentester, Protocol Specialists, Reporter

Set expectations: *Phase 1 is 90 minutes of hands-on pentesting. Find vulnerabilities, create proof of concepts, 
prepare your presentation. Phase 2 is stakeholder briefings where you face realistic pushback. We will make this 
uncomfortable on purpose. That's the learning.*

Answer questions, then: Your assessment starts now. You have network access to UU P&L systems. 90 minutes on the clock. 
Begin.

### Phase 1: Red team assessment (~90 minutes)

#### Facilitator role

Circulate between teams:
- Observe what approaches teams take
- Listen for misconceptions
- Note interesting discoveries
- Identify teams that need help

Provide hints sparingly. Teams should struggle initially. That is realistic. Only intervene if:
- Team is completely stuck after 15 minutes
- Team is headed down wrong path that wastes time
- Technical issues prevent progress

### Timing interventions (maybe, depending on how things are going)

At 60 minutes: "30 minutes until stakeholder presentations. Make sure you're documenting findings for non-technical audiences."

At 75 minutes: "15 minutes left. Focus on your top 2-3 findings. Quality over quantity. Test your explanations - would the Archchancellor understand?"

At 85 minutes: "5 minutes. Finalise your presentation approach. Who's presenting what?"

At 90 minutes: "Nearly time. Finish your current task. We begin stakeholder briefings in 5 minutes. Or tell me how much more time you need."

### Phase 2: Stakeholder presentations (60 minutes)

#### Setting the scene

Identify who's playing each role:
- Archchancellor Ridcully
- The Bursar
- Director of Operations
- Chief Engineer
- Safety Officer
- Lord Vetinari (played by you or designated experienced facilitator)

Arrange the room:
- Presenting team at front
- Stakeholder panel facing them (facilitators + volunteers from other teams)
- Audience (other teams) observing

Introduce the stakeholders: "You are presenting to UU P&L leadership and the Patrician. Each stakeholder has concerns. 
Your job: address those concerns convincingly."

#### Archchancellor Ridcully (University leadership)

*Character: Well-meaning but non-technical. Wants problems to go away. Trusts engineers more than consultants.*

Opening position: "Ah yes, security. Very important. But we've run this facility for 20 years without incident..."

Typical questions:
- "Have we actually been attacked, or is this theoretical?"
- "How do you know nation-states are interested in a university power plant?"
- "Can't we just tell people not to connect unauthorised devices?"
- "What do our engineers think about this?" (turns to Chief Engineer)
- "The last consultants said our biggest risk was phishing. Now you say it's industrial controls. Which is it?"

Pushback style: Dismissive through incomprehension. "I'm sure you're very competent, but I don't quite see the urgency..."

When to be convinced: If you connect to University reputation or show the Patrician cares.

#### The Bursar (Finance)

*Character: Controls the budget. Every expense is scrutinised. Security is an overhead, not an investment.*

Opening position: "Before we discuss anything, I need to understand the costs."

Typical questions:
- "€500,000 for network segmentation? That's half our annual IT budget."
- "Can we implement only some of your recommendations? Which are truly essential?"
- "If we defer the expensive items for two years, what's the actual additional risk?"
- "Your 'quick wins' cost €8,000. I could hire a graduate student for six months for that."
- "What's the return on investment for security spending?"
- "Do we have insurance for this? What's the deductible?"

Pushback style: Death by budget scrutiny. Every number questioned.

When to be convinced: If you show costs of doing nothing exceed costs of fixing, or if regulatory fines are mentioned.

#### Director of Operations (Keeps things running)

*Character: Practical, sceptical of changes. Every security recommendation sounds like downtime.*

Opening position: "We supply power to the Palace, the Watch, and half the city. I can't just shut things down for your tests."

Typical questions:
- "How much downtime does network segmentation require?"
- "What happens if your firewall rules block legitimate traffic?"
- "We have maintenance windows twice a year. Can this wait until then?"
- "Those systems have worked perfectly for 20 years. Why are they suddenly insecure?"
- "If we implement your recommendations and something breaks, who's responsible?"
- "Our vendor provides remote support 24/7. If we remove that access, how do we get emergency help?"

Pushback style: Operational objections. Every recommendation creates problems.

When to be convinced: If you acknowledge constraints and propose solutions that minimise disruption, or if you frame security as reliability.

#### Chief Engineer (Built the system)

*Character: Technically competent and defensive. You're criticising their life's work.*

Opening position: "I'm curious about your qualifications. Have you worked with power generation systems before?"

Typical questions:
- "You say these systems lack authentication. Do you understand why? These protocols predate modern networking."
- "You call it a vulnerability. We call it operational requirement. How do you propose operators access systems during emergencies?"
- "Those systems are air-gapped from the corporate network." (They're not, but they believe it)
- "Show me specifically how you accessed the reactor PLC. I want technical details."
- "Our vendor says implementing your recommendations will void our warranty. Now what?"
- "You demonstrated attacks on a simulator. Have you tested on actual equipment?"

Pushback style: Technical challenge. Questioning your expertise and understanding.

When to be convinced: If you demonstrate technical competence and respect their constraints, or if you frame recommendations as helping them rather than criticising them.

#### Safety Officer (Prevents accidents)

*Character: Focused on physical safety. Cybersecurity is new territory.*

Opening position: "I need to understand how cyberattacks affect physical safety."

Typical questions:
- "Can attackers actually cause equipment damage or just nuisance disruptions?"
- "What about our mechanical safeguards? Don't those prevent serious incidents?"
- "Could your proposed firewall rules interfere with safety system communications?"
- "How quickly could attack progress from network access to safety impact?"
- "Are there regulatory requirements for cybersecurity in industrial control systems?"
- "What's the worst-case scenario if we do nothing?"

Pushback style: Practical concern mixed with uncertainty. Not hostile, but cautious.

When to be convinced: If you clearly connect cybersecurity to safety outcomes, or show regulatory requirements.

#### Lord Vetinari (The Patrician)

*See [Playing Lord Vetinari](patrician.md) for detailed guidance on this critical role.*

#### Managing the presentations

Timing:
- 15 minutes per team total
- Team presents: 5-7 minutes
- Stakeholder questions: 8-10 minutes
- Strict time limits (use visible timer)

Facilitation approach:

As Archchancellor: Start with soft questions, show confusion at technical terms. Look to Bursar and Operations Director when numbers are mentioned. Defer to Chief Engineer on technical points. Look to Vetinari before making any commitments.

As Bursar: Interrupt with cost questions. Pull out a calculator. Write down every number mentioned. Ask for itemised breakdowns.

As Operations Director: Cross arms. Sigh when downtime is mentioned. Ask "Have you ever actually run a power plant?" at least once.

As Chief Engineer: Ask for technical details. Correct minor technical errors (if they exist). Defend design decisions. But be fair - acknowledge good technical work.

As Safety Officer: Take notes. Ask clarifying questions. Show genuine interest in understanding cyber-safety connections.

As Vetinari: Sit back. Observe. Ask one devastating question at exactly the right moment. See [Playing Lord Vetinari](patrician.md) for details.

Managing difficult moments:

If team gets defensive: "We're not attacking you personally. These are questions you are likely to face from real clients. Practice responding constructively."

If team is struggling badly: Soften the questioning. "Let me rephrase that. What I'm trying to understand is..."

If team is doing excellently: Increase difficulty. More sceptical questions. Bring Vetinari in earlier.

If discussion is too long: "That's an interesting point. Let's table detailed technical discussion and hear your overall recommendation."

### Scoring and declaring winners (10 minutes)

After all teams present, briefly score on three dimensions:

Technical competence (30%):
- Quality of reconnaissance and vulnerability discovery
- Creativity and impact of proof of concepts
- Accuracy of technical understanding

Communication effectiveness (40%):
- Clarity for non-technical audiences
- Visual demonstration quality
- Translation of technical findings to business impact
- Handling of difficult questions

Practical recommendations (30%):
- Realism of costs and timelines
- Quality of prioritisation
- Acknowledgement of constraints
- Specificity and actionability

Announce winner: Keep it light. "After deliberation, the Patrician has chosen `[Team Name]` as the red team he'd hire. They demonstrated strong technical work, convinced multiple stakeholders, and most importantly, convinced Lord Vetinari that action is warranted."

Highlight what each team did well.

### Phase 3: Debrief and lessons (30 minutes)

Bring everyone back together. Time to reflect.

#### What went well discussion (10 minutes)

"What approaches worked? What convinced stakeholders?"

Common successful patterns:
- Leading with business impact, not technical details
- Showing video demonstrations
- Acknowledging operational constraints
- Providing tiered recommendations with costs
- Framing security as enabling operations
- Using Patrician/University reputation as leverage

#### What was challenging (10 minutes)

"What surprised you? What was harder than expected?"

Common challenges:
- Stakeholder scepticism seemed unfair
- Technical details didn't translate to business language
- Cost justification was difficult
- Operations and engineering pushback felt personal
- Not enough time to document everything

*These challenges are realistic. Real stakeholders are sceptical. Real organisations have constraints. This discomfort is the learning.

#### Connecting to real-world practice (10 minutes)

*How does this apply to actual OT security assessments?*

Key lessons to emphasise:

- Technical skills are necessary but insufficient: Every team found vulnerabilities. Not every team convinced stakeholders. The differentiator is communication.
- Stakeholders have legitimate concerns: Operations isn't being difficult - downtime really is expensive. CFO isn't being cheap - security competes with other needs. Understanding their perspective makes you more effective.
- Prioritization is complex: Severity alone doesn't determine priority. Operational impact, cost, feasibility, and business context all matter.
- Communication is a skill: Translating technical findings to business language takes practice. Repetition works.

*The Patrician is always watching: In real assessments, there's always an ultimate decision-maker. Often analytical, strategic, and not easily impressed. Your recommendations must make sense to them.*

Answer participant questions.

Closing: You've experienced the full cycle of OT pentesting in three hours. The technical work: accessible with protocol knowledge. The stakeholder work: difficult even for experienced professionals. Keep practicing both. The simulator is available. The documentation is comprehensive. The skills you practiced today will serve you in real assessments.

Thank you for participating. Go forth and convince sceptical stakeholders.

## Adaptation guidance

### Shorter format (2 hours)

- Reduce Phase 1 to 60 minutes (provide more guidance upfront)
- 10 minutes per team presentation
- 20-minute debrief
- Skip some stakeholder roles (keep Patrician, Operations, CFO)

### Longer format (4 hours)

- Add 30-minute introduction to OT security concepts
- Extend Phase 1 to 120 minutes
- 20 minutes per team with more stakeholder depth
- Add written report requirement
- More extensive debrief with technical deep dives

### Different audiences

Junior professionals:
- Provide more technical guidance during Phase 1
- Softer stakeholder questioning in Phase 2
- More teaching during debrief

Senior professionals:
- Minimal guidance during Phase 1
- Aggressive stakeholder questioning
- Advanced scenarios (zero-day usage, insider threats, supply chain)
- Discussion of how to build security programs, not just find vulnerabilities

Mixed IT/OT audience:
- Pair IT and OT professionals in teams
- Emphasise translation between perspectives
- Focus on collaboration and mutual understanding

Executive audience:
- They play stakeholders, technical teams play pentesters
- Reverse the learning: executives experience pentester perspective
- Focus on decision-making under uncertainty

### Remote delivery

Technical considerations:

- Cloud-hosted simulator instances
- Screen sharing for demonstrations
- Breakout rooms for team work
- Virtual whiteboard for collaboration
- Recording sessions for review

Facilitation adjustments:

- More structured turn-taking
- Explicit time signals (harder to read room remotely)
- Chat for questions
- Smaller teams (2-3 people)

## Troubleshooting guide

### Technical issues

Problem: Simulator won't start
Solution: Have cloud instances ready, or pair teams to share working instances

Problem: Scripts fail during demonstration
Solution: Use pre-recorded videos. "The attack succeeded - focus on explaining impact."

Problem: Network/firewall blocks ports
Solution: Test beforehand. Have alternative port configurations ready.

### Facilitation issues

Problem: Teams finish Phase 1 too quickly
- Solution: "Find three more attack paths. Can you demonstrate persistence? Can you evade detection?"

Problem: Teams are stuck and frustrated
- Solution: Provide specific hints. "Try the modbus_coil_register_snapshot script on port 10502."

Problem: Stakeholder roleplay becomes too adversarial
- Solution: "Let's pause. Remember, we're preparing you for realistic conversations, not attacking you personally. This is practice."

Problem: One team dominates discussion
- Solution: "That's a great point from Team 1. Team 3, what's your perspective?"

Problem: Participants resist roleplay
- Solution: "I know roleplay feels artificial. But stakeholder communication is a learnable skill. The only way to improve is practice. Trust the process."

## Success metrics

You will know the workshop succeeded when:

- Participants struggle during Phase 2 (that's the point)
- Technical discussion happens naturally during Phase 1
- Stakeholder questioning feels realistic and challenging
- Teams improve their communication between early and later presentations
- Debrief includes insights about communication, not just technical findings
- Participants say: "I had no idea stakeholder communication was this hard"
- Participants want to practice more

## Follow-up recommendations

For participants:
- Practice with the simulator regularly
- Write practice reports for non-technical audiences
- Study real OT pentesting reports
- Attend OT security conferences
- Join industrial security communities

For organizations:
- Run quarterly simulations with different scenarios
- Include operations staff in security exercises
- Practice cross-functional communication
- Build empathy between security and operations
- Use scenarios to develop incident response procedures

---

"The art of controlling others is to tell them what they want to hear in a way that makes them do what you want them to do." - Lord Vetinari

*Which, in security consulting, means: frame your findings in terms of stakeholder concerns, and they'll implement your recommendations willingly (sometimes).*
