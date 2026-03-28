# Reconnaissance for social engineering

Social engineering reconnaissance is different from technical reconnaissance. You are not looking for open ports
or unpatched services. You are looking for names, relationships, routines, and the specific vocabulary of an
organisation: the words they use for things, who reports to whom, what systems they use, and who in the building
is likely to hold a door open for a stranger carrying a laptop bag.

Most of this information is publicly available. Organisations and their employees share it freely, because
individually none of it looks sensitive. The useful part of social engineering recon is aggregating it.

## LinkedIn

LinkedIn is, among other things, a remarkably detailed organisational chart maintained voluntarily by the people
on it. A target organisation's employee list reveals the management structure, the names of people in IT, HR,
finance, and facilities, the job titles used internally, and the tenure of key staff. Someone who joined six months
ago is more likely to be uncertain about internal processes and more likely to defer to an apparently authoritative
outsider.

Job postings are often more useful than employee profiles. A posting for a "Microsoft 365 administrator" tells
you the organisation runs Exchange Online. A posting for a "ServiceNow developer" tells you their ITSM platform.
A posting for a "Qualys engineer" tells you their vulnerability management tooling. All feeds into
more convincing technical pretexts. People are more willing to help someone who knows the name of the thing they
are supposedly there to fix.

## Email formats and domains

Most organisations use a consistent email format: firstname.lastname, f.lastname, firstname, or some variation.
A single confirmed email address, often findable via data breach databases, press releases, or conference
speaker listings, is usually enough to work out the format for the whole organisation. Tools like Hunter.io
formalise this process, but manual inference often works just as well.

Knowing the email format matters when constructing phishing lures, spoofed sender addresses, or plausible
internal referrals. "I got your name from j.henderson@targetorg.com" is more convincing than a vague reference
to someone in IT.

## Social media and forums

Employees discussing work frustrations on Reddit, Twitter, or specialist forums often reveal more than they
intend to. A complaint about the VPN being unreliable tells you the VPN product. A question on a helpdesk forum
about a specific error message tells you the software and version. A photo posted from the office reveals
building layout, badge designs, and sometimes computer screens in the background.

Security staff are not immune to this. A SOC analyst describing an interesting incident, a sysadmin asking for
help with a configuration, or a developer committing to a public repository with internal hostnames or API
endpoints in the code all constitute reconnaissance material, even when they were not intended as such.

## Public documents

Annual reports, board meeting minutes, grant applications, and press releases reveal strategic priorities,
upcoming projects, key vendors, and named contacts. For regulated industries, filings with industry bodies
or government agencies often contain organisational structure and contact details that would otherwise require
considerable effort to find.

Tender documents and procurement notices are particularly useful. They describe what the organisation is
buying, from whom, on what timeline, and who is responsible for the project. An attacker posing as a vendor
responding to a live procurement process is much more convincing than one who appears from nowhere.

## What you are building

By the end of the reconnaissance phase you should know: the name and role of at least one person you can
reference in a pretext, the email format and a plausible sending domain, the technology platforms in use
at the target, the physical location and layout of the relevant site, and the vocabulary the organisation
uses for its own processes and systems.

That is enough to build a pretext that will survive the level of scrutiny most employees apply to a request
that sounds roughly legitimate.

## Playbooks

- [Playbook: Physical access engagement](../playbooks/physical-entry.md) — the recon checklist is the first phase of this playbook
