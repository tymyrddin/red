# Insider facilitation

Most social engineering targets a barrier: a person who controls access to something the
attacker wants, and who needs to be bypassed or deceived. Insider facilitation targets a
different kind of person: someone already inside the perimeter whose cooperation, willing or
otherwise, provides access more directly than any external technique.

The distinction is operational. A barrier is an obstacle to route around. An insider
is an asset to develop. The approach, timeline, and deniability considerations are different
in each case.

## Witting cooperation

A cooperative insider knows they are helping an unauthorised party. Developing that cooperation
requires identifying a motivation and a mechanism.

Financial incentive is the most direct. People with access to valuable systems and a gap
between their compensation and their expenses are the most likely candidates. The approach
is usually indirect at first: a conversation that establishes the relationship before the
ask, or a platform that makes the offer without naming the requester. The size of the initial
offer is less important than its credibility: an offer that feels plausible for the scale of what
is being requested is more effective than one that is either insultingly small or implausibly
large.

Ideological alignment is slower to develop but more stable. A person who has convinced
themselves that the organisation they work for deserves what is about to happen will take
greater risks and require less ongoing management. Identifying ideological candidates during
reconnaissance means paying attention to public complaints, professional disputes, and the
gap between an individual's stated values and their employer's public behaviour.

Coercion is the most operationally difficult path: the leverage needs to be real, the
target needs to believe the attacker will use it, and the risk of escalation is
considerably higher than with voluntary cooperation. It appears in targeted attacks where
the access is sufficiently valuable and no cooperative path exists, but it introduces
instability that voluntary arrangements do not.

## Unwitting participation

An unwitting insider cooperates without understanding that they are doing so. The target
believes their actions are legitimate; the attacker has constructed a pretext that makes
the requested action appear routine.

The most common form is a convincing instruction that causes the insider to perform an
action the attacker cannot perform directly: creating an account, approving an exception,
forwarding a document to an external address, disabling a security control for a
"maintenance window". The instruction appears to come from an authority the insider
recognises and trusts. The insider has no reason to question it.

Remote access tooling installed under a plausible pretext is another mechanism. An insider
who installs a "monitoring agent" or "IT support tool" at the request of someone they
believe is from their IT department has provided the attacker with a persistent foothold
they did not technically authorise. The insider's culpability is minimal; the access is
real.

Unwitting participation is lower-risk than witting cooperation because the insider is not
a co-conspirator with their own motivations and the ability to change their mind. The
failure mode is different: the insider may eventually realise what happened and report it,
rather than proactively turning informant or negotiating a higher price.

## Identifying viable targets

Recon for insider development looks different from recon for a phishing campaign. The
question is not who holds a door open or who clicks links: it is who has the specific
access required, what their relationship with the organisation looks like, and what
pressure points exist.

Tenure is a useful initial filter. Someone who recently left is worth investigating: exit
circumstances are sometimes acrimonious, and access is sometimes not fully revoked
immediately. Someone who has been in the same role for a long time without promotion
may have accumulated both access and grievance. Recent hires are easier to approach
with legitimate-looking requests because they are still mapping the organisation's
social landscape.

Access profile, mapped against the engagement objective, narrows the field. There is
little value in developing an insider with no relevant access. LinkedIn, job postings,
and organisational directories provide enough to estimate who controls what.

Public signals of dissatisfaction are not a guarantee, but they are a starting point:
Glassdoor reviews, forum complaints, the tone of someone's LinkedIn activity in the
months before they leave a role. None of these are conclusive, but an insider programme
based on targets who show some signal is more efficient than one that is purely random.

## Operational security

An insider who knows they are cooperating is a liability as well as an asset. The
picture is narrow but unforgiving: communication channels that do not trace back, a
relationship structure that limits what the insider knows about the larger operation,
and a plan for what happens if the insider changes their mind or is discovered.

An unwitting insider is simpler in this respect: they do not know enough to disclose
anything meaningful. The risk is the audit trail their actions leave, and the
possibility that incident response will eventually reconstruct what happened and trace
it back to the instruction the insider received.
