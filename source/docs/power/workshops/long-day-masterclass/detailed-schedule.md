# Full-Day Simulation: Detailed Facilitator Schedule

*Minute-by-minute guide for running the UU Power & Light extended roleplay*

## Overview

This detailed schedule provides specific guidance for each segment of the 6.5-hour simulation (plus breaks = ~8 hours total). Use this to stay on track, know what to do when, and handle common situations.

**Key principle:** Keep things moving. Participants will want more time for everything. Constraints are realistic - real engagements have deadlines.

---

## Pre-event preparation (1 week before)

### Technical setup

- [ ] Clone and test simulator on facilitator machine
- [ ] Verify all scripts work
- [ ] Prepare cloud instances OR test local installation instructions
- [ ] Create backup: pre-recorded attack videos
- [ ] Test remote delivery tools (if applicable)

### Materials preparation

- [ ] Print role assignment cards (15-20 sets)
- [ ] Print stakeholder persona cards (5-6 sets)
- [ ] Print prioritization matrix worksheets (5-6 copies)
- [ ] Print implementation plan templates (10 copies)
- [ ] Prepare presentation templates (digital, shared folder)
- [ ] Create timing slides (projected countdown timers)
- [ ] Prepare Patrician question cards (special set)

### Communications

- [ ] Send participant installation instructions
- [ ] Send pre-reading materials (optional)
- [ ] Confirm venue/virtual space
- [ ] Test A/V equipment
- [ ] Prepare music/timer for breaks

---

## Morning: Discovery and Assessment (3.5 hours)

### 09:00-09:30 (30 min): Setup and briefing

**09:00-09:10: Welcome and overview**

*Facilitator script:*

"Good morning. Welcome to the UU Power & Light security assessment simulation. Today you'll experience a complete red team engagement from discovery through remediation. This is not a lecture. This is experiential learning through roleplay.

The scenario: You've been hired to assess UU Power & Light, the primary electricity supplier for Unseen University and Ankh-Morpork. Your client: the Archchancellor. Your ultimate stakeholder: Lord Vetinari, Patrician of the city.

You'll play different roles. You'll face realistic constraints. You'll negotiate, compromise, and defend your recommendations. By end of day, you'll understand that security work is 20% technical, 80% people.

Questions before we begin?"

**09:10-09:20: Role assignment**

Divide participants into roles:
- Red team: 4-5 people (assess, exploit, report)
- Blue team: 2-3 people (current security, remediation planning)
- Operations: 2-3 people (keep systems running, push back on disruption)
- Leadership: 2-3 people (Archchancellor, Bursar, Safety Officer)
- Patrician: 1 person (facilitator or experienced participant)

*Selection criteria:*
- Red team: Most technical participants
- Blue team: Mix of technical and communication skills
- Operations: Practical mindset, willing to be "difficult"
- Leadership: Strong presentation skills, comfortable challenging
- Patrician: Most experienced participant or facilitator

Hand out role cards with objectives, constraints, and freedoms.

**09:20-09:30: Technical setup and access**

- Verify all participants can access simulator
- Troubleshoot installation issues (pair people if needed)
- Test basic connectivity (can they run scripts?)
- Share collaboration documents (reports, worksheets)
- Answer technical questions

*Facilitator checks:*
- [ ] All teams have working simulator access
- [ ] All teams understand their role objectives
- [ ] Shared documents accessible to all
- [ ] Timer visible

**09:30: Official start**

"Your engagement begins now. Red team: you have network access to UU P&L systems. Blue team and Operations: document current posture. Leadership: prepare your questions. Two hours until initial findings briefing. Begin."

*Start visible countdown timer: 2 hours*

---

### 09:30-11:30 (2 hours): Red team assessment

**Red team objective:** Reconnaissance, vulnerability discovery, PoC development, initial findings

**What they should be doing:**
- 09:30-10:00: Network discovery, protocol identification
- 10:00-10:45: Protocol-specific enumeration, vulnerability assessment
- 10:45-11:30: PoC development, evidence gathering, findings documentation

**Facilitator role: Circulate and observe**

*Visit red team every 15 minutes:*
- 09:45: "What have you found so far? Any surprises?"
- 10:00: "You've had 30 minutes. What protocols are exposed? What's your target priority?"
- 10:15: "Have you tested authentication? What can you access without credentials?"
- 10:30: "One hour left until briefing. Start thinking about your top 3 findings for initial presentation."
- 10:45: "What proof of concepts are you building? Remember your audience - make it visual."
- 11:00: "30 minutes left. Focus on documentation. What evidence do you have?"
- 11:15: "15 minutes. Finalize your preliminary findings. Who's presenting what?"

*Common issues and interventions:*

**Issue:** Team is stuck, not finding anything
**Intervention:** "Have you tried the modbus_identity_probe script? Port 10502 is interesting..."

**Issue:** Team found one thing, stopped looking
**Intervention:** "You found Modbus. What about S7? OPC UA? What protocols are running on other ports?"

**Issue:** Team is going too deep on one system
**Intervention:** "That's interesting, but you need breadth for initial briefing. Come back to deep dive after you map the full attack surface."

**Issue:** Team is creating too many PoCs
**Intervention:** "Pick your 2 most impactful attacks. Quality over quantity. Make them convincing."

**Blue team + Operations objective:** Document current posture, prepare context

**What they should be doing:**
- Document what security controls exist (if any)
- List maintenance windows and operational constraints
- Identify critical systems and dependencies
- Prepare questions about findings
- Understand what changes are feasible

**Facilitator role: Provide context documents**

Give them:
- Network diagram (rough - they can refine)
- List of existing security "controls" (minimal - maybe antivirus, basic firewalls)
- Maintenance schedule (2 windows per year, 4 days each)
- Budget constraints (€100K annual security budget, already allocated)
- Operational constraints (downtime = €10K/hour)

*Check-ins:*
- 10:00: "What security controls currently exist? Make a list - it's probably short."
- 10:45: "Start thinking about what red team will find. What's your response going to be?"
- 11:15: "Prepare questions for red team. What do you need to know to assess their recommendations?"

**Leadership objective:** Prepare questions and concerns

**What they should be doing:**
- Understand facility importance
- Review budget situation
- Prepare stakeholder questions
- Discuss priorities

**Facilitator role: Brief them on character**

*Archchancellor:* "You care about University reputation. You don't understand technical details. You want problems to go away cheaply."

*Bursar:* "Every recommendation gets the question: How much? The budget is tight. Security competes with new turbine you actually need."

*Safety Officer:* "You care about physical safety. You need to understand cyber-physical connection. You're potentially an ally if they frame it right."

Give them question cards to prepare.

**11:30 checkpoint:**
- Red team has preliminary findings ready
- Blue team and Operations have context documented
- Leadership has questions prepared

---

### 11:30-11:45 (15 min): Morning break

*Announce: "15-minute break. Back at 11:45 for initial findings briefing. Red team: finalize your top findings. Everyone else: prepare your questions."*

**During break, facilitator:**
- Assess red team progress (are findings adequate?)
- Prep briefing room (projector, timer)
- Print any materials needed for afternoon
- Reset for briefing session

---

### 11:45-12:30 (45 min): Initial findings briefing

**Setup:** Red team presents to Blue team + Operations (Leadership observes but doesn't engage yet)

**Structure:**
- Red team presentation: 15 minutes
- Technical Q&A and discussion: 20 minutes
- Planning discussion: 10 minutes

**11:45-12:00: Red team presentation**

*Facilitator introduction:*
"Red team will present preliminary findings. This is a technical briefing for Blue team and Operations. Be honest about what you found, what you don't know yet, and what you need to investigate further."

Red team should cover:
- Assessment methodology
- Systems discovered
- Protocols identified
- Key vulnerabilities found (top 5)
- Brief PoC demonstrations (1-2)
- Areas for deeper investigation

*Facilitator role: Keep time, manage flow*
- 5-minute warning
- Cut off if over time

**12:00-12:20: Technical Q&A**

Blue team and Operations ask questions:
- "How did you access that?"
- "Is that system actually reachable from corporate network?"
- "What authentication did you need?"
- "Can you demonstrate that again?"

*Facilitator injects operational reality:*
- "Operations: Is that system critical? What happens if it's compromised?"
- "Blue team: Do we have any controls that would detect or prevent this?"
- "Operations: Red team says they can shut down turbines. Walk us through the restart procedure and time required."

**12:20-12:30: Planning discussion**

Collaborative discussion:
- What additional investigation is needed?
- What PoCs are most important to develop?
- What findings need more evidence?
- What should the final report focus on?

*Facilitator guides:*
"Red team: This afternoon you write the full report. Based on this feedback, what's your priority?"

"Blue team and Operations: You'll be developing remediation plans this afternoon. What do you need from the report?"

**12:30 checkpoint:**
- Red team knows what to focus on for report
- Blue team and Operations understand findings
- Leadership has heard initial findings (observing)

---

### 12:30-13:30 (1 hour): Lunch break

*Announce: "One hour lunch. Afternoon session begins at 13:30. This afternoon: report writing, remediation planning, and stakeholder presentations. Enjoy your lunch."*

**Participants can:**
- Take actual lunch break (recommended)
- Red team: Discuss report approach
- Blue/Ops: Discuss remediation challenges
- Leadership: Prepare tough questions

**Facilitator during lunch:**
- Assess morning progress
- Adjust afternoon timing if needed
- Prepare afternoon materials
- Set up breakout spaces for afternoon work

---

## Afternoon: Remediation and Presentations (4 hours)

### 13:30-15:00 (1.5 hours): Report writing and remediation planning

**13:30-13:35: Afternoon kickoff**

*Facilitator:*
"This afternoon focuses on remediation. Red team: write comprehensive report. Blue team and Operations: develop realistic remediation plans. Leadership: prepare for presentations. You have 90 minutes of intense work, then we move to prioritization workshop.

Red team: Your report should have executive summary, detailed findings (minimum 10), and recommendations. Use the template in shared folder.

Blue team and Operations: Review findings, assess feasibility, identify constraints, propose alternatives where needed.

Leadership: Review budget, prepare hard questions, think about priorities.

Begin."

**13:35-15:00: Parallel work sessions**

**Red team: Report writing**

*Activities:*
- Executive summary (business language)
- Technical findings (detailed, with evidence)
- Remediation recommendations (tiered)

*Facilitator check-ins:*
- 14:00: "30 minutes in. How many findings documented? Need at least 10 with evidence."
- 14:30: "Executive summary readable by non-technical people? Test it on someone."
- 14:45: "15 minutes left. Finalize recommendations. Three tiers: quick wins, medium-term, strategic."

*Common issues:*

**Issue:** Report too technical
**Intervention:** "Would the Archchancellor understand this? Rewrite in business language."

**Issue:** Findings without evidence
**Intervention:** "Every finding needs a screenshot or log output. No evidence = no finding."

**Issue:** Recommendations vague
**Intervention:** "Don't say 'improve security.' Say 'deploy Modbus firewall rules restricting access to IPs X, Y, Z.'"

**Blue team + Operations: Remediation assessment**

*Activities:*
- Review each red team finding
- Assess operational impact of recommendations
- Identify constraints (downtime, budget, staff)
- Propose alternative solutions
- Develop feasibility matrix

*Facilitator check-ins:*
- 14:00: "Which red team recommendations are operationally feasible? Which are problematic?"
- 14:30: "For problematic recommendations, what are alternatives? Don't just say no - propose solutions."
- 14:45: "Prepare your pushback. What will you challenge in prioritization workshop?"

*Give them realism prompts:*
- "Network segmentation: €500K, 6 months, 32 hours downtime across 2 maintenance windows. Is that worth it?"
- "Jump host: Changes admin workflows. Every engineer pushback. How do you handle?"
- "Removing vendor access: Emergency support response time goes from 4 hours to 24+ hours. Acceptable?"

**Leadership: Strategic planning**

*Activities:*
- Review budget constraints
- Identify competing priorities
- Prepare questions for presentations
- Discuss approval criteria

*Facilitator provides context:*
- "Budget: €100K annual security, already allocated. New money requires University Council approval (months)."
- "Competing priorities: New turbine needed (€2M), salary increases (€200K), building maintenance (€300K)."
- "Patrician: Watching. Multiple security recommendations on his desk. Why prioritize this?"

*Give them question cards:*
- Budget questions for Bursar
- Operational questions for Archchancellor
- Safety questions for Safety Officer
- Strategic questions for group

**15:00 checkpoint:**
- Red team has draft report with 10+ findings
- Blue team + Operations have remediation assessment
- Leadership has questions prepared

---

### 15:00-15:15 (15 min): Afternoon break

*Announce: "15-minute break. Return at 15:15 for prioritization workshop where all teams work together."*

**Facilitator during break:**
- Quick review of red team report (adequate?)
- Assess Blue/Ops remediation assessment (realistic?)
- Set up room for prioritization workshop (tables, worksheets)
- Prepare prioritization matrix on whiteboard/slide

---

### 15:15-16:15 (1 hour): Remediation prioritization workshop

**Setup:** All teams except Leadership work together (Leadership observes, takes notes on arguments used)

**15:15-15:20: Workshop introduction**

*Facilitator:*
"This workshop: Take red team findings and prioritize using objective framework. Everyone has a voice. Red team provides technical context. Operations provides operational context. Blue team facilitates.

Framework uses 5 factors:
1. Safety impact (1-5)
2. Operational impact (1-5)
3. Exploitation likelihood (1-5)
4. Business impact (1-5)
5. Remediation feasibility (1-5, higher = easier)

Priority score = Risk score / Feasibility

We'll score the top 10 findings together, then you'll organize into 3-tier roadmap."

*Display matrix on screen/whiteboard*

**15:20-15:50: Scoring top findings (30 min)**

Work through 10 findings, ~3 minutes each:

*Process for each finding:*

1. **Red team describes finding** (1 min)
   "Unauthenticated Modbus access to turbine PLCs. Anyone on network can read or write to any register. No authentication mechanism exists in protocol."

2. **Teams debate scoring** (2 min)
   - Red team: "Safety impact is 4 - they can cause overspeed."
   - Operations: "Actually 5 - safety interlocks can also be manipulated via Modbus."
   - Blue team: "Agreed, 5. Operational impact?"
   - Operations: "5 - can shut down all turbines."
   - Red team: "Likelihood is 5 - no authentication, network-accessible, trivial to exploit."
   - Blue team: "Business impact 5 - major disruption to city services."
   - Operations: "But remediation feasibility is 4 - firewall rules are relatively easy."

3. **Facilitator records** consensus scores

*Facilitator role: Manage debate, push for decisions*

"30 seconds left on this finding. What's consensus on operational impact - 4 or 5?"

"Good debate, but we need to move on. Calling it: safety impact 5, operational 5, likelihood 5, business 5, feasibility 4. Priority score 7.0. Next finding."

*Inject realism:*
"Operations: If we implement this fix, does it affect your maintenance procedures?"
"Red team: You say likelihood is 5. Have you seen evidence of actual attempts to access these systems?"
"Blue team: Feasibility 5 means easy. What's your confidence we can implement in 30 days?"

**15:50-16:05: Organize into roadmap (15 min)**

*Facilitator:*
"You've scored 10 findings. Now organize into 3 tiers:
- Tier 1 (0-30 days): Quick wins, high impact, low disruption
- Tier 2 (30-90 days): Medium complexity, planned downtime
- Tier 3 (6-12 months): Strategic initiatives, major investment

You have 15 minutes. Go."

*Teams work on shared whiteboard/document:*
- Drag findings into tiers
- Justify placement
- Estimate rough costs per tier
- Identify dependencies (must do X before Y)

*Facilitator interventions:*

**If too many Tier 1:**
"Tier 1 is 30 days and €8,000 budget. You have 8 items totaling €45,000. Choose."

**If nothing in Tier 3:**
"Network segmentation didn't make the cut? Explain that to the Patrician."

**If no quick wins:**
"Archchancellor will ask: What can you show me in 30 days? What's your answer?"

**16:05-16:15: Roadmap review and approval (10 min)**

Leadership team (who has been observing) provides feedback:

*Archchancellor:* "Explain Tier 1 in language I understand. What happens in 30 days?"

*Bursar:* "€500,000 total. Where does that come from? Annual budget is €100K."

*Safety Officer:* "Which recommendations improve safety? Which might affect safety systems?"

Teams defend and adjust.

*Facilitator:*
"You have a roadmap. Not everyone agrees yet. That's what stakeholder presentations are for. 15-minute break, then presentations begin."

**16:15 checkpoint:**
- Prioritized remediation roadmap exists
- Findings organized into 3 tiers
- Rough costs estimated
- Dependencies identified
- Teams prepared to defend choices

---

### 16:15-16:30 (15 min): Final break before presentations

*Announce: "Final break. Back at 16:30 for stakeholder presentations. Red team: practice your pitch. Leadership: sharpen your questions. Blue team and Operations: prepare to support or challenge as needed."*

**Facilitator during break:**
- Review roadmap (does it make sense?)
- Prepare presentation space
- Brief Patrician role (if separate person)
- Set up timer for presentations
- Final preparations

---

### 16:30-17:30 (1 hour): Stakeholder presentations

**Three presentations to different audiences, building in complexity**

**16:30-16:45: Technical briefing (15 min)**

**Audience:** Blue team + Operations
**Presenter:** Red team
**Format:** Detailed technical discussion

*Content:*
- Assessment methodology
- Detailed findings with evidence
- PoC demonstrations
- Technical recommendations
- Q&A

*Facilitator role: Keep time, ensure technical accuracy*

"Blue team: Any technical questions?"
"Operations: Does this match your understanding of the systems?"

*Purpose: Verify technical correctness before executive briefing*

**16:45-17:05: Executive briefing (20 min)**

**Audience:** Archchancellor, Bursar, Safety Officer
**Presenters:** Red team + Blue team (joint presentation)
**Format:** Business language, visual demonstrations

*Structure:*
- Executive summary (3 min): What we found, what it means
- Demonstrations (5 min): 2-3 convincing PoCs with business context
- Risk assessment (3 min): What could happen, how likely
- Recommendations (5 min): 3-tier roadmap with costs
- Q&A (4 min): Handle stakeholder questions

*Facilitator plays Leadership roles:*

**As Archchancellor:**
- "I don't understand 'Modbus protocol.' Explain like I'm five."
- "Have we been attacked? No? Then what's the urgency?"
- "Can't we just tell people to use stronger passwords?"

**As Bursar:**
- "€500,000. That's half our annual IT budget."
- "Can we do Phase 1 only? What's the risk?"
- "How does this compare to industry norms? Is this excessive?"

**As Safety Officer:**
- "Which findings affect safety systems?"
- "Could your remediation recommendations interfere with safety interlocks?"
- "What's the worst-case safety scenario?"

*Red team + Blue team must:*
- Translate technical to business language
- Defend cost estimates
- Explain priorities
- Handle pushback
- Negotiate compromises

**17:05-17:30: Patrician briefing (25 min)**

**Audience:** Lord Vetinari
**Presenters:** Red team + Blue team + CISO
**Format:** Strategic discussion

*This is the final boss*

**17:05-17:15: Presentation (10 min)**

Teams present focused on city-level concerns:
- Why this matters to Ankh-Morpork (not just University)
- Strategic risk assessment
- Comparison to other city risks
- Resource allocation justification
- Request for approval

**17:15-17:30: Patrician interrogation (15 min)**

*Facilitator as Vetinari (see masterclass-red-team-patrician.md for detailed guidance)*

*Key questions to ask:*

"You've demonstrated what's possible. Convince me it's probable."

"I have €500,000. I can spend it on this, on Watch intelligence, or on grain silo security. Make the case for your option."

"You recommend removing vendor remote access. University has a contract guaranteeing 4-hour response. How do you maintain that?"

"If I implement all recommendations, what happens when the next red team finds new vulnerabilities? Are we in a perpetual cycle?"

*Approach:*
- Analytical, not hostile
- Probing for strategic thinking
- Testing whether they understand context
- Looking for evidence-based arguments

*Possible outcomes:*

**If teams do well:**
"Archchancellor, I suggest implementing Tier 1 recommendations immediately while the Bursar works with them on phased funding for Tier 2 and 3. I'll expect quarterly progress reports."

**If teams do poorly:**
"This seems premature. I suggest you refine your analysis and return in one month with more complete cost-benefit justification."

**If teams do okay:**
"I'll approve Tier 1 immediately. Tier 2 and 3 require more detailed planning and University Council approval. Show me Phase 1 results in 90 days."

**17:30 checkpoint:**
- Teams have presented to all stakeholders
- Patrician has rendered judgment
- Negotiations have occurred
- Final recommendations emerging

---

### 17:30-17:45 (15 min): Final negotiation and decisions

**All teams together** (including Leadership and Patrician)

*Facilitator moderates final discussion:*

"Based on presentations and Patrician guidance, let's finalize the path forward."

**Agenda:**
1. Confirm Tier 1 recommendations (3 min)
   - What's approved immediately?
   - Who owns what?
   - What's the timeline?

2. Adjust Tier 2/3 based on feedback (5 min)
   - What requires more analysis?
   - What's deferred?
   - What dependencies exist?

3. Establish governance (3 min)
   - Who reports to whom?
   - What are review milestones?
   - How is progress measured?

4. Final approval (4 min)
   - Leadership provides formal approval
   - Patrician provides final guidance
   - Handshakes and acknowledgments

*Facilitator ensures:*
- Specific commitments, not vague promises
- Realistic timelines
- Clear ownership
- Measurable outcomes

*End state:*
- Written summary of approved actions
- Owners assigned
- Timeline established
- Review process defined

---

### 17:45-18:00 (15 min): Debrief and lessons learned

**Step out of character** - everyone drops their roles

*Facilitator:*
"Let's debrief. What did you learn? What was hardest? What will you take back to your work?"

**Discussion prompts:**

**For red team:**
- "Was finding vulnerabilities the hard part, or convincing people?"
- "What surprised you about stakeholder reactions?"
- "How would you approach reporting differently next time?"

**For blue team / operations:**
- "How did it feel to defend operational constraints?"
- "Where did you find common ground with red team?"
- "What made prioritization difficult?"

**For leadership:**
- "What made you approve or reject recommendations?"
- "What arguments were most convincing?"
- "How did you balance competing priorities?"

**For Patrician:**
- "What strategic thinking did you see or not see?"
- "When were teams most convincing?"
- "What would you recommend they improve?"

**For everyone:**
- "What's different about OT security vs IT security?"
- "Why is remediation harder than discovery?"
- "What skills do you need to develop?"
- "How does this apply to real-world work?"

**Key lessons to emphasize:**

1. **Technical work is the easy part** - Finding vulnerabilities took 2 hours. Remediation took 4.
2. **Stakeholders have legitimate concerns** - Operations isn't being difficult; downtime really is expensive.
3. **Communication is a skill** - Translating technical to business language requires practice.
4. **Prioritization is complex** - Severity alone doesn't determine what to fix first.
5. **Collaboration matters** - Security vs Operations is lose-lose. Security + Operations is win-win.
6. **Strategic thinking differentiates** - Anyone can find vulnerabilities. Not everyone can explain why they matter.

**Closing:**
"You've experienced a complete security engagement in one day. Real engagements take weeks or months, but the phases are the same. The skills you practiced - technical assessment, communication, negotiation, prioritization - these are what separate adequate security professionals from exceptional ones.

The simulator is yours to keep practicing. The frameworks are reusable. The experience is yours.

Thank you for engaging fully with this simulation. Go forth and convince skeptical stakeholders."

**18:00: Official end**

---

## Post-event follow-up

### Within 24 hours

- [ ] Send thank you email to participants
- [ ] Share simulation outputs (reports, roadmaps, presentations)
- [ ] Provide access to resources (frameworks, templates, guides)
- [ ] Share photos/videos (if captured)

### Within 1 week

- [ ] Send feedback survey
- [ ] Compile lessons learned
- [ ] Update facilitation guide based on experience
- [ ] Share outcomes with broader community

### Ongoing

- [ ] Maintain contact with participants
- [ ] Share real-world OT security news/incidents
- [ ] Offer follow-up simulations with different scenarios
- [ ] Build alumni network

---

## Troubleshooting common issues

### Technical problems

**Issue:** Simulator won't start for some participants
**Solution:** Pair them with working teams, or use pre-recorded attack videos

**Issue:** Scripts fail during demonstrations
**Solution:** "Due to technical issues, here's a video of the attack succeeding. Focus on explaining impact."

**Issue:** Network/firewall blocks necessary ports
**Solution:** Have cloud instances as backup, or run simulation on isolated network

### Timing problems

**Issue:** Red team taking too long
**Solution:** "Hard stop in 10 minutes. Prioritize your top 5 findings and move on."

**Issue:** Too much discussion in prioritization workshop
**Solution:** "Good debate. Time's up. Facilitator decides: Safety impact is 5. Moving on."

**Issue:** Presentations running long
**Solution:** Use visible countdown timer. "Wrap up your thought. Next presenter."

### Content problems

**Issue:** Red team findings too shallow
**Solution:** Inject hints during break. "Have you tested write access? Have you tried extracting PLC logic?"

**Issue:** Recommendations too vague or unrealistic
**Solution:** During lunch, provide feedback: "Network segmentation requires costs, timeline, and downtime estimates."

**Issue:** Stakeholder questioning too soft
**Solution:** Facilitator as Patrician brings necessary difficulty

### Interpersonal problems

**Issue:** Conflict between teams (operations vs security tension)
**Solution:** "This tension is realistic, but let's keep it professional. Focus on solving problems together."

**Issue:** One participant dominating
**Solution:** "Good point from Sarah. John, what's your perspective?"

**Issue:** Disengagement from some participants
**Solution:** Assign them specific roles: "Tom, you're playing the Chief Engineer. You need to defend the current architecture."

---

## Success metrics

The simulation succeeded if:

- [ ] Red team found substantial vulnerabilities (10+ findings)
- [ ] Prioritization required hard choices (not enough resources for everything)
- [ ] Stakeholder presentations were uncomfortable (pushback was realistic)
- [ ] Negotiations occurred (not just acceptance or rejection)
- [ ] Participants felt challenged but not defeated
- [ ] Debrief revealed learning (not just complaints about difficulty)
- [ ] Participants want to do it again (with different scenarios)

The ultimate success metric: Participants say, "I had no idea how hard stakeholder management was. I need to practice this more."

Because that realization is the first step toward becoming effective at OT security work.

---

*"The purpose of education is to prepare for what you don't know you'll need." - Ponder Stibbons*

*This simulation prepares participants for the hardest part of security work: convincing people to care and act.*

*Mission accomplished if they leave uncomfortable, enlightened, and determined to improve.*
