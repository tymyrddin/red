# Overview

*A ~3-Hour Practical Workshop in OT Security Pentesting and Stakeholder Management*

You are a red team hired to assess the security of Unseen University Power & Light Co., the primary electricity 
supplier for Ankh-Morpork. Your job: find vulnerabilities, create proof of concepts, and convince stakeholders to act.

The technical assessment is straightforward. The real challenge? Convincing the Archchancellor, the Bursar, the Chief 
Engineer, and ultimately Lord Vetinari that your findings matter enough to justify change.

This is experiential learning through roleplay. You can conduct a real penetration test using the UU P&L simulator, 
then face sceptical stakeholders who question your findings, your costs, and your credibility.

## What you can do

Phase 1: Red team assessment (90 minutes)
- Network reconnaissance of industrial control systems
- Protocol-specific vulnerability discovery (Modbus, S7, OPC UA, EtherNet/IP)
- Proof of concept development demonstrating real-world attack impact
- Documentation of findings for stakeholder presentation

Phase 2: Stakeholder briefing (60 minutes)
- Present findings to UU leadership and the Patrician
- Face realistic pushback and challenging questions
- Defend your recommendations under scrutiny
- Negotiate priorities and timelines

Phase 3: Debrief (30 minutes)
- Compare approaches across teams
- Discuss communication strategies that worked (and didn't)
- Extract lessons for real-world assessments

## Who might benefit

- Security professionals transitioning to OT/ICS security
- Penetration testers expanding into industrial systems
- Red team operators working with critical infrastructure
- Security consultants who need to present to non-technical stakeholders
- Anyone who needs to convince sceptical executives to fund security

## What you can learn

Technical skills:
- Industrial protocol reconnaissance techniques
- OT vulnerability assessment methodology
- Creating convincing proof of concepts
- Multi-stage attack campaign development

Communication skills:
- Translating technical findings into business impact
- Handling stakeholder pushback and difficult questions
- Prioritising remediation under real-world constraints
- Negotiating with operations, finance, and leadership

Strategic skills:
- Understanding stakeholder motivations and concerns
- Framing security in terms that matter to different audiences
- Balancing technical accuracy with practical communication
- Building coalitions for security improvements

## Why this matters

Finding vulnerabilities in OT systems is easy. Industrial protocols have minimal security. With network access, 
you can often control critical systems in minutes.

The hard part? Convincing people to fix what you found.

Operations will push back on downtime requirements. Finance will question every cost estimate. Engineers will 
defend their designs. And executives will ask why they should care about theoretical risks when systems have 
"worked fine for 20 years."

This workshop prepares you for the real challenge: not finding problems, but driving solutions.

## Prerequisites

- Basic networking knowledge (TCP/IP, ports, protocols)
- Familiarity with security concepts (reconnaissance, exploitation, reporting)
- Command-line comfort (Bash, Python)
- No prior OT experience required

## Workshop format

Duration: 3 hours

Team structure: Small groups (3-4 people) conducting independent assessments

Competition element: Teams compete for best technical demonstration and most convincing stakeholder presentation

Roleplay component: Facilitators play UU stakeholders with realistic concerns and pushback

Hands-on focus: 90 minutes of actual pentesting, 60 minutes of presentation roleplay

## Required setup

Participants need:
- Laptop (Linux, macOS, or Windows with WSL)
- Python 3.12+
- Git access to the simulator repository
- 4GB RAM minimum

Installation:
```bash
git clone https://github.com/ninabarzh/power-and-light-sim.git
cd power-and-light-sim
pip install -r requirements.txt
python tools/simulator_manager.py
```

## Difficulty level

Technical: Intermediate (scripts are provided, protocol knowledge taught during exercise)

Communication: Advanced (stakeholder management is deliberately challenging)

Overall: This workshop is more difficult than participants expect. The technical work is accessible. The stakeholder 
roleplay is designed to be uncomfortable and realistic. But fun! At least experienced as fun later.

## What makes this different

Most OT security training focuses on finding vulnerabilities. This workshop focuses equally on convincing people to fix them.

Most pentesting courses teach technical exploitation. This workshop teaches stakeholder communication under pressure.

Most security training uses lectures and demos. This workshop uses experiential roleplay where you make decisions and face consequences.

You learn by doing. You learn by struggling. You learn by experiencing realistic pushback from operations, finance, and leadership.

## Learning outcomes

By completing this workshop, you will:

- Conduct reconnaissance and exploitation against industrial control systems
- Create proof of concepts that demonstrate impact to non-technical audiences
- Present technical findings in business language
- Handle defensive responses and budget objections
- Prioritise remediation considering operational and financial constraints
- Understand why technical competence alone is insufficient for effective OT security work

## The Patrician factor

The ultimate challenge: convincing Lord Vetinari, Patrician of Ankh-Morpork, that UU Power & Light's security matters to the city.

He will ask the questions you don't want to answer:
- "How does this compare to other risks facing the city?"
- "What evidence suggests anyone would target a university power plant?"
- "Your recommendations seem designed to justify your continued employment."
- "What happens if I do nothing?"

[The Patrician](https://indigo.tymyrddin.dev/docs/vetinari/) is not hostile. He is analytical, strategic, and focused 
on stability. He will listen to evidence. He will not be rushed or impressed by severity ratings.

If you can convince Vetinari, you can convince anyone.

## Next steps

This 3-hour masterclass provides practical introduction to OT security assessment and stakeholder management. For 
deeper learning:

- Comprehensive OT security training: 2-3 day workshops covering full methodology
- Advanced exploitation techniques: Nation-state TTPs and sophisticated attack chains
- Detection and defence: Blue team perspective and monitoring strategies
- Full-day simulation: University student program with extended roles and remediation focus

## Support materials

- Detailed scenario documentation
- Facilitator guide
- Stakeholder persona scripts
- Example reports and presentations
- Technical reference materials

## Ready to begin?

The UU Power & Light network is waiting. The vulnerabilities are there. The stakeholders are sceptical.

Can you prove the threat is real? Can you convince them to act?

Find out in three hours.

---

*"The thing about security is that insecurity is so much cheaper." - Lord Vetinari (probably)*
