# Trends

## Data-first extortion

Ransomware used to encrypt and demand payment for decryption. That model
is increasingly superseded by one that steals first and threatens to
publish. Encryption is optional; the threat of disclosure is sufficient.
Dual and triple extortion models combine:

- Threat to publish stolen data (primary leverage)
- Encryption of production systems (operational pressure)
- DDoS against public services during negotiations (reputational pressure)

The shift to data-first extortion means that offline backups no longer
constitute a full recovery path. The data is already gone.

## Business process attacks

Fraud via business process abuse is growing. These attacks exploit
legitimate workflows rather than technical vulnerabilities:

- Invoice manipulation: changing payment details on a legitimate invoice
  in transit or in the document management system
- Payroll diversion: altering bank account details in the HR system to
  redirect salary payments
- SaaS workflow abuse: exploiting approval workflows, financial
  authorisations, or procurement systems that lack adequate controls

Red teams now simulate fraud, not just breaches. The question is whether
the organisation's financial and HR workflows can be abused without
triggering any security alert.

## Cross-domain impact chains

Modern impact scenarios combine multiple attack vectors in sequence:

Helpdesk social engineering leads to an MFA bypass, which gives access to
a VPN, which reaches a financial SaaS platform, which allows a wire transfer
authorisation. No exploit anywhere. Just a chain of legitimate-looking steps.

The pattern: identity abuse enables access, process abuse enables impact.
Technical controls that monitor for malware miss this entirely.

## AI-assisted impact

Automated lateral movement, autonomous agent-based attack chains, and
AI-driven decision making in attack tools are early-stage but emerging.
More concretely, AI tools now help attackers write more convincing social
engineering content, generate targeted disinformation, and accelerate the
reconnaissance that makes business process attacks possible.

## Reputation and trust attacks

Impact that targets narrative rather than infrastructure:

- Deepfake audio and video used for impersonation at scale
- Data poisoning: corrupting datasets or model training data
- Selective leaks of sensitive information designed to damage reputation
  or create regulatory pressure

These attacks require no persistence and no ongoing technical access. A
single successful data theft, used strategically for leaks and narrative
manipulation, can cause more lasting damage than a ransomware deployment.

# The uncomfortable truth for red teams

Modern red teaming must simulate the full impact chain, not just the
initial compromise. A red team that stops at "we have domain admin" has
not demonstrated the business impact that a real adversary would achieve.

The questions that matter:

- Can we manipulate a financial workflow without triggering security?
- Can we exfiltrate data that would be material for regulatory disclosure?
- Can we cause operational disruption that the organisation could not
  recover from in a defined time window?
- Can we operate for 30 days without being detected?

If the answers are yes, the engagement has found something worth fixing.
