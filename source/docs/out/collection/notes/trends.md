# Trends

## Identity is the new perimeter

SaaS admin panels, SSO providers, and OAuth applications have replaced the
fileserver. Attackers who control a valid identity control everything that
identity can reach, which in modern environments is extensive. Helpdesk
social engineering leading to a password reset, followed by MFA fatigue or
consent phishing, is now a primary red team objective. No exploit needed.

## AI-enhanced social engineering

Spear phishing has become industrial. Deepfake voice and video lower the
cost of impersonation. Hyper-personalised lures at scale are produced by
language models rather than by hand. Phishing-as-a-service kits handle
MFA bypass, QR phishing, and obfuscation as a commodity. The artisanal
era of social engineering is over.

## Supply chain and dependency poisoning

NPM and PyPI packages compromised at scale, CI/CD pipeline abuse, and
developer tooling compromise have made the software supply chain a primary
collection vector. Rather than attacking an endpoint, attackers compromise
an upstream dependency that ships to hundreds of organisations simultaneously.

## AI systems as attack surface

Prompt injection against tool-using agents causes data leakage and
cross-system action chains. LLM-integrated applications that trust model
output without validation become conduits for collection. MITRE ATLAS is
expanding rapidly to cover AI-specific attack techniques.

## Shadow IT and shadow AI harvesting

Employees leak sensitive data into unapproved SaaS tools and AI services.
Unmonitored SaaS sprawl creates data stores the organisation does not know
exist. In these cases collection becomes passive: the organisation exfiltrates
itself, and the attacker simply waits.

# What this means for red teams

Modern collection engagements simulate identity abuse and process exploitation
rather than endpoint compromise. The question is not "can we access the
fileserver?" but "can we become an identity that owns the data, and can we
do it without triggering detection?"

The red team evolution table captures this shift:

| Old framing         | New framing                                |
|---------------------|--------------------------------------------|
| Can we hack in?     | Can we operate like a real adversary?      |
| Exploits            | Identity and process abuse                 |
| One-off engagements | Continuous validation                      |
| Technical scope     | Whole organisation (people, process, tech) |

Red teams are now testing whether the organisation can be manipulated, not
just compromised.

# The uncomfortable bottom line

Attacks are multi-stage supply chains, not single exploits. Attackers chain
weak signals into strong outcomes. No single clever hack; just relentless
composition of legitimate-looking steps.

What collection looks like in 2026:

- It looks like a user logging into SharePoint
- It looks like an OAuth application requesting consent
- It looks like a CI/CD pipeline pulling a dependency
- It looks like an employee using an AI assistant

None of these look like an attack. All of them can be one.
