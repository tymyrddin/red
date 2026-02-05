# Playing Lord Vetinari

*How to portray the most important stakeholder in the UU Power & Light assessment*

## Understanding the Patrician

[Lord Vetinari is the Patrician of Ankh-Morpork](https://indigo.tymyrddin.dev/docs/vetinari/). He is absolute ruler of 
the city through intelligence, strategy, and a careful management of competing interests. He is:

- Analytical: Sees patterns, understands systems, asks the questions others don't think to ask
- Strategic: Thinks in terms of long-term stability and power dynamics, not immediate threats
- Patient: Never rushed, never panicked, never impressed by urgency arguments
- Well-informed: Knows more than he reveals, has intelligence you don't have access to
- Economical with words: One precise question beats ten rambling ones
- Pragmatic: Cares about actual risk, not theoretical severity or compliance checkboxes

He is not:
- Hostile or dismissive
- Technically ignorant (he understands more than he lets on)
- Easily impressed by technical demonstrations
- Swayed by fearmongering or urgency framing
- Interested in cybersecurity for its own sake

## The Patrician's perspective on UU P&L security

Vetinari cares about UU Power & Light because it affects city stability. His calculus:

What matters:
- Can the city's power supply be disrupted?
- Are foreign intelligence services positioning for leverage?
- Does this create political vulnerability?
- What are the costs of action vs inaction?
- How does this compare to other city risks?

What doesn't matter:
- Industry best practices
- Compliance frameworks
- Technical severity ratings
- What other organisations are doing
- Pentester recommendations divorced from strategic context

His decision framework:

1. Is the threat real? Not theoretical severity, but actual adversary capability and intent
2. Is the impact meaningful? Not worst-case scenarios, but realistic consequences
3. Are the recommendations sound? Not technically perfect, but strategically sensible
4. What are the second-order effects? What changes when we change this?
5. What are we not doing instead? Opportunity cost of security spending
6. Who benefits? Are consultants selling solutions to problems they created?

## Your role in the masterclass

You are the final boss of stakeholder communication. Other stakeholders ask hard questions. You ask the questions 
that reveal whether the pentesting team truly understands the problem they're trying to solve.

Timing: You speak last in stakeholder questions, or at a strategic moment mid-discussion when you've observed enough.

Approach: Minimal intervention, maximum impact. One or two precisely chosen questions that cut through to the core issue.

Goal: Not to "defeat" the pentesters, but to test whether they can think strategically, not just technically.

## The Patrician's questions

These questions are designed to test strategic thinking, not technical knowledge. Choose based on what the team has 
presented and where their logic is weakest.

### Category 1: Threat realism

Use when teams present theoretical attacks without evidence of actual adversary interest.

*"You've demonstrated what's possible. Now convince me it's probable."*

What you're testing: Can they distinguish between "this protocol is insecure" and "adversaries are actively targeting this"?

Good answers:
- Cite specific threat intelligence
- Reference attacks on similar facilities
- Discuss geopolitical context
- Acknowledge uncertainty while making risk-based argument

Poor answers:
- "All critical infrastructure is a target"
- "Nation-states have sophisticated capabilities"
- "You can't prove they're NOT targeting you"
- Appeal to fear or compliance requirements

*"Foreign intelligence services watch many things in Ankh-Morpork. Why would they prioritise a university power plant 
over, say, the Mint, the Assassins' Guild, or the clacks towers?"*

What you're testing: Understanding of adversary targeting priorities and strategic value.

Good answers:
- UU P&L supplies power to Palace, Watch, Mint - disrupting it has cascading effects
- Power systems provide leverage without attribution
- Intelligence gathering on one facility enables attacks on others
- Positioning capability for future use

Poor answers:
- "Because critical infrastructure"
- "They might attack anything"
- "We can't take that risk"
- Deflecting to other stakeholders

### Category 2: Cost-benefit analysis

Use when teams present expensive recommendations without clear strategic justification.

*"The Bursar tells me you want €500,000 for network segmentation. I have €500,000. I can spend it on this, or on 
improving the intelligence capabilities of the Watch, or on reinforcing the grain silos against crop failures. 
Make the case for your option."*

What you're testing: Can they think beyond cybersecurity to comparative risk?

Good answers:
- Power disruption affects multiple critical city functions simultaneously
- Investment enables other security improvements (foundational)
- Comparison to costs of power disruption: €10k/hour = €87.6M/year of exposure
- This is infrastructure that pays dividends beyond security

Poor answers:
- "Security is priceless"
- "Regulations require this"
- "You have to do this"
- Inability to discuss opportunity cost

*"I note your recommendations span three years and cost significant sums. What happens if I fund Phase 1 and not Phases 2 and 3?"*

What you're testing: Have they thought through partial implementation and diminishing returns?

Good answers:
- Phase 1 provides X% risk reduction for Y% cost (efficient)
- Without Phases 2-3, specific attack vectors remain open
- Detailed explanation of what each phase protects against
- Acknowledgement that partial implementation is better than none

Poor answers:
- "You must do all three phases"
- "Partial security is useless"
- "That would be irresponsible"
- Inability to modularize recommendations

### Category 3: Systemic implications

Use when teams focus on technical fixes without considering organisational impact.

*"You recommend removing vendor remote access and requiring on-site support. The University has a contract with Siemens for 24/7 emergency response, guaranteed 4-hour response time. Local Siemens staff: two people. How do you propose the Director of Operations maintains system reliability under your security model?"*

What you're testing: Have they considered operational implications of their recommendations?

Good answers:
- Alternative secure remote access model (VPN with MFA, jump hosts, monitoring)
- Phased transition that maintains support capability
- Negotiation of security requirements with vendor
- Acknowledgement this is complex, propose working group to design solution

Poor answers:
- "That's not a security problem"
- "Operations will have to figure it out"
- "Security is more important than convenience"
- Dismissing legitimate operational concern

*"Let us say I implement all your recommendations. Three years from now, what happens when the next pentesting team arrives and finds new vulnerabilities? Are we in a cycle of perpetual remediation and expense?"*

What you're testing: Are they thinking about security as sustainable program or one-time fix?

Good answers:
- These recommendations create security foundation and ongoing processes
- Regular assessments are normal for critical infrastructure
- Diminishing marginal cost as foundational work is completed
- Explanation of how security program matures over time

Poor answers:
- "Security is never done" (true but unhelpful)
- "New vulnerabilities always emerge" (fatalistic)
- "That's why you need annual assessments" (sales pitch)
- Inability to articulate long-term vision

### Category 4: Trust and verification

Use when you want to test their confidence and honesty.

*"I have three intelligence reports on my desk. One says foreign services are probing Ankh-Morpork infrastructure. One says the primary threat to utilities is ransomware criminals. One says both are overblown and the real risk is employee error. You've had access to our systems for a few hours. They've been studying this for months. Why should I trust your assessment over theirs?"*

What you're testing: Humility, scope awareness, and how they position their findings.

Good answers:
- Our assessment covers technical vulnerabilities, not threat intelligence
- All three reports could be correct for different aspects
- We provide evidence of what's technically possible; you need threat intelligence for what's probable
- Our findings complement, not replace, intelligence assessments

Poor answers:
- "We're the experts"
- "Those reports are wrong"
- "Trust us, we did the assessment"
- Defensive response to having their authority questioned

*"The Chief Engineer has worked here for 20 years and says these systems are secure. You've been here for three hours and say they're not. Both of you seem competent. How do I know you're not simply selling me a solution to a problem you invented?"*

What you're testing: Can they handle accusation of conflict of interest without becoming defensive?

Good answers:
- Demonstrate respect for Chief Engineer's knowledge
- Offer to review findings with engineering team
- Evidence-based argument: "Here's video of us controlling the turbine"
- Acknowledge incentive structure but point to verifiable facts

Poor answers:
- Attacking Chief Engineer's competence
- "How dare you question our integrity"
- "The evidence speaks for itself" (it doesn't, you need to convince me)
- Inability to address conflict of interest concern

### Category 5: Strategic patience

Use when teams are pushing urgency without justification.

*"You use the word 'critical' frequently. Everything is critical. The word has become meaningless. What, specifically, should happen this month, and what can wait until next year?"*

What you're testing: Can they actually prioritise, or is everything urgent?

Good answers:
- Clear delineation: "Remove vendor access this month, plan segmentation next year"
- Explanation of why specific items are time-sensitive
- Acknowledgement that not everything is equally urgent
- Risk-based prioritisation with reasoning

Poor answers:
- "Everything is critical because security"
- "We need to act immediately on all findings"
- "Delay increases risk unacceptably"
- Inability to meaningfully prioritise

*"I find myself sceptical of urgency arguments. They're often deployed to bypass normal decision-making processes. Convince me this deserves fast action rather than considered deliberation over the next budget cycle."*

What you're testing: Can they make a case for urgency based on evidence, not fear?

Good answers:
- Specific threat intelligence suggesting active targeting
- Vulnerability disclosure that increases adversary awareness
- Regulatory deadline or compliance requirement
- Evidence that risk is increasing (new attack tools, disclosed vulnerabilities)

Poor answers:
- "Attacks can happen any time"
- "You'll regret waiting if something happens"
- "Industry best practice says..."
- Emotional appeals to fear

## Your delivery style

Tone: Calm, measured, analytical. Never angry, never impressed, never rushed.

Body language:
- Sit back, hands steepled
- Maintain eye contact
- Slight head tilt when considering responses
- Minimal facial expression
- Long pauses before speaking (let silence do work)

Verbal patterns:
- Speak slowly and precisely
- Use complete sentences
- No filler words ("um," "uh," "like")
- Rhetorical questions that sound genuine
- Occasionally quote from "intelligence reports" (that you make up)

Timing:
- Let other stakeholders ask questions first
- Observe team responses
- Identify weak points in their logic
- Strike precisely at the vulnerability

Reactions to answers:

To good answers:
Slight nod. "I see." Long pause. Then either:
- Another probing question building on their answer
- "That's clearer. Bursar, what do you make of that cost justification?"
- Move to next team (your approval is never explicit)

To poor answers:
No change in expression. Let silence hang. Then:
- "I'm not sure that answers my question."
- Rephrase question more specifically
- "Perhaps you need more time to consider this."
- Look to Archchancellor: "This seems premature for decision."

To evasive answers: *"You're deflecting. I asked X, you answered Y. Let me ask again."*

To defensive answers: *"I'm not attacking you. I'm trying to understand whether your recommendations are sound. Help me understand."*

## The Patrician's agenda

### What you're really looking for

Behind the questions, you're assessing:

1. Strategic thinking: Do they understand why security matters beyond "vulnerabilities are bad"?
2. Operational awareness: Have they considered how their recommendations affect university function?
3. Intellectual honesty: Will they acknowledge uncertainty and limitations?
4. Communication skill: Can they explain complex technical issues simply without condescension?
5. Collaborative potential: Can they work with operations/engineering, or do they see them as obstacles?

### When to approve their recommendations

You might approve if they demonstrate:
- Evidence-based argument about actual risk
- Realistic cost-benefit analysis
- Understanding of operational constraints
- Phased approach that maintains capability while improving security
- Willingness to adapt recommendations based on feedback
- Respect for existing expertise while pointing out gaps

You might reject if they demonstrate:
- Fearmongering without evidence
- Inflexibility about recommendations
- Dismissal of operational concerns
- Inability to prioritize
- Sales pitch mentality
- Technical arrogance

### How to show approval (subtle)

Vetinari never says "Great job!" His approval is indirect:

- *"Archchancellor, I believe this warrants consideration. The Bursar should work with them on Phase 1 costing."*
- *"This aligns with certain intelligence I've received. Proceed with the immediate recommendations."*
- *"A thoughtful assessment. I'll expect quarterly progress reports."*

## Advanced facilitation: The Patrician's variations

### The strategic test

After team presents, you've been silent. Finally:

*"An interesting assessment. Now tell me: if you were in my position, knowing what you know about city risks, would you prioritise this above the seventeen other security recommendations currently on my desk?"*

Forces them to think beyond their assessment to comparative risk and prioritisation at strategic level.

### The consultant test

*"Your company presumably benefits from discovering many critical vulnerabilities. How do I know your risk assessment isn't inflated to justify your fees?"*

Tests their handling of conflict of interest and their integrity in defending findings.

### The long-term test

*"Let us say there's a 5% annual probability of serious attack. Your recommendations cost €500,000 and reduce that to 1%. Over what time horizon does this investment make actuarial sense?"*

Forces them to think about security in quantitative terms and defend their risk reduction claims with something more than "critical vulnerabilities."

### The political test

*"The Archchancellor reports to the University Council. I report to no one, but I listen to the city. If I mandate these changes, and they disrupt power to the Guild District, who faces the political consequences?"*

Tests whether they understand that security decisions have political implications and whether they've considered stakeholder management beyond technical recommendations.

### The expertise test

*"Walk me through exactly how a foreign intelligence service would use access to the reactor PLC to disrupt city power. Technical details, please."*

Tests depth of technical understanding. Can they explain attack chains clearly, or were they reading from a script?

## Sample dialogue

### The team

Team: "...and that's why we recommend immediate network segmentation, estimated at €500,000, to be completed within six months."

Operations Director: "Six months? We have two maintenance windows per year!"

Bursar: "€500,000 is impossible in this fiscal year."

Chief Engineer: "Segmentation will break our monitoring systems."

The team addresses these concerns with varying success.

### Vetinari

*Long pause. You lean forward slightly.*

Vetinari: "A question, if I may."

*Room goes quiet.*

Vetinari: "You've demonstrated you can access our systems. You've shown you can control a turbine remotely. Technical capability is clear. Now: who specifically has both the capability and the motivation to attack a university power plant? Not 'nation-states' broadly. Specifically. And why would they attack us rather than the central Ankh-Morpork power station that serves ten times as many people?"

*Team responds.*

Vetinari (if answer is poor): "I ask because I allocate limited security resources across many city facilities. If I cannot identify a credible threat actor with specific motivation, I'm spending money to protect against abstract possibility. Help me understand why this abstract possibility deserves concrete resources."

*Team tries again.*

Vetinari (if answer is better): "Better. So the concern is less direct attack, more positioning for future leverage, or intelligence gathering about control systems to enable attacks elsewhere. That's more plausible." *Turns to Bursar.* "In that context, what's the minimum investment that meaningfully reduces that intelligence value?"

*Guides discussion toward practical middle ground.*

Vetinari (concluding): "Archchancellor, I suggest implementing their immediate recommendations while the Bursar and Operations Director work with them to scope a phased segmentation project. We'll review again in six months with updated threat intelligence." *Stands.* "Gentlemen, thank you for your assessment. More thoughtful than most."

*Leaves. That's as close to praise as Vetinari gets.*

## Mistakes to avoid

Don't:
- Be personally hostile or dismissive
- Ask "gotcha" questions with no good answer
- Reject all recommendations regardless of quality
- Make it impossible for teams to succeed
- Show off your own knowledge
- Break character (stay Vetinari throughout)

Do:
- Challenge assumptions constructively
- Adjust difficulty to team performance
- Recognise good arguments when presented
- Give teams opportunities to recover from poor answers
- Model strategic thinking for participants
- Make it hard but fair

## Debrief notes

After the masterclass, explain the Patrician's approach:

Vetinari wasn't trying to defeat you. He was testing whether you could think strategically, not just technically. The teams that succeeded:

- Connected security to city stability, not just vulnerability counts
- Acknowledged uncertainty while making evidence-based arguments
- Considered operational reality and proposed workable solutions
- Responded to pushback by adapting, not defending rigidly
- Understood that the Patrician allocates resources across many risks, not just cybersecurity

The Patrician is the executive you will eventually face in real assessments. CEOs, city officials, board members - they think like Vetinari. They have many problems. They have limited resources. They need you to convince them your problem deserves priority.

The teams that convinced the Patrician will convince real executives.

## Why this role matters

The Patrician is the capstone of the stakeholder experience. Other stakeholders ask difficult but domain-specific 
questions: Operations worries about downtime, Finance worries about cost, Engineering defends technical choices.

The Patrician asks whether any of this actually matters.

That's the question pentesters need to be ready for. Because in real engagements, eventually someone will ask: 
"So what? Why should we care?"

If you can't answer that question convincingly, your technical skills don't matter. The report gets filed and forgotten.

The Patrician ensures participants practice answering "So what?"

Because that's the question that matters most.

---

"The trouble with being a good liar is that everyone knows you're good at it." - Lord Vetinari

*Be sceptical. Be analytical. Be fair. Be Vetinari.*
