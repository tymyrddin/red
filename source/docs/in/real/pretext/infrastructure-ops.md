# Social engineering of infrastructure operators

Network and routing infrastructure operators are a specific social engineering audience with
their own reconnaissance surface, their own institutional vocabulary, and their own set of
trusted relationships that a convincing pretext can exploit. The access they hold is different
from what a helpdesk agent or a finance team member controls: a network operator who makes
a routing configuration change under a manipulated pretext can affect traffic at scale, and
a routing security administrator who makes an error in a Route Origin Authorisation can
invalidate legitimate routes for an entire organisation or prefix block.

The social engineering is not technically complex. It runs on the same trust dynamics as any
other impersonation: someone who sounds like they belong, references the right systems and
processes, and creates plausible urgency is difficult to dismiss, particularly when the
call arrives during an incident or a maintenance window.

## Reconnaissance

Public routing infrastructure exposes more identity information than most operators realise.

WHOIS records and Regional Internet Registry (RIR) databases, RIPE, ARIN, APNIC, LACNIC,
and AFRINIC, list administrative and technical contacts for every registered Autonomous System
and IP address block. These records include names, email addresses, and sometimes phone
numbers, updated by the operators themselves. The maintainer handles in routing registries
identify the specific individuals responsible for route objects and RPKI data.

BGP looking glasses operated by transit providers and internet exchange points reveal peering
relationships and routing policy. Knowing that a target AS peers with specific upstream
providers, and knowing those providers' support contact structures, is enough to construct
a credible pretext as a peer or upstream contact.

NANOG, RIPE, and APNIC mailing list archives are public and extensively indexed. Network
engineers discuss configuration problems, routing incidents, and vendor issues by name and
organisation. The mailing lists are a detailed professional directory with technical context
attached.

Conference presentations, NOC blog posts, and published network incident reports often
identify named engineers alongside the systems and processes they manage. A post-incident
review that names the person who handled a BGP misconfiguration also identifies that person
as someone with the relevant access for a future pretext.

## Pretexts

RIR support impersonation is among the most effective starting points. RIPE NCC, ARIN, and
APNIC all have support processes for verifying account ownership, updating resource
registrations, and handling routing security queries. An email or call that presents as
routine account maintenance, a request to verify authorisation for a prefix registration,
or a notification about a compliance requirement can prompt operators to take actions they
would otherwise initiate only internally.

Peering request context is plausible in almost any network engineering conversation. A
call from an engineer at another AS discussing a routing issue, or an email thread about
a technical problem affecting traffic between the two networks, creates a natural reason
to exchange information about internal routing policies, configurations, and contacts.

Audit and compliance framing resonates in environments that have deployed RPKI or are
working towards routing security certification. An approach framed as a MANRS (Mutually
Agreed Norms for Routing Security) compliance review, an ISOC routing security assessment,
or a vendor security audit gives an external contact a reason to ask about routing
configurations without raising the same suspicion as a more direct approach.

Vendor maintenance is reliable in environments that use specific router platforms. An
engineer from Cisco, Juniper, or Nokia TAC who calls during a maintenance window to
walk through a configuration review has a legitimate reason to discuss routing tables,
policy filters, and authentication credentials for management interfaces.

## Configuration error induction

The goal is not always to obtain access directly. Causing an operator to make an incorrect
configuration change can serve the same purpose without requiring credential theft.

An email that presents as a peer network's NOC reporting a routing problem, and that
includes specific (incorrect) suggested configuration changes to resolve it, may result in
the target operator making those changes. A call that describes an active routing incident
and walks the operator through a "fix" that actually introduces a misconfiguration achieves
the same outcome through social pressure and the operational context of a real or
manufactured incident.

ROA (Route Origin Authorisation) configuration errors are particularly useful. The
MaxLength attribute in an ROA controls which more-specific prefixes are considered valid.
An operator who is walked through "correcting" a MaxLength value to a broader setting
inadvertently authorises route announcements they did not intend to permit.

## Operational procedure manipulation

Change management processes in network operations typically involve maintenance windows,
change authorisation tickets, and out-of-band approval for significant reconfigurations.
Each of these creates a social engineering surface.

Maintenance window notifications are often sent from generic email addresses and follow
predictable templates. An attacker who has observed the format of a target organisation's
change notifications can send a credible notification that moves a window, changes an
approval contact, or requests that a specific engineer be available, positioning a
subsequent call within the expected context of an authorised change.

Incident response creates the most favourable conditions. An operator responding to an
active routing problem is under time pressure, focused on resolution, and less likely to
pause for verification steps they would ordinarily complete. Injecting a false update
into an incident response chain, or calling during a real incident with an authoritative
voice and specific technical details, exploits exactly the conditions under which careful
verification is most difficult.

## Cross-references

- [Reconnaissance for social engineering](recon.md): general recon techniques that apply to this audience
- [Building a cover identity](personas.md): constructing the persona for a network engineer or RIR support role
- [Elicitation](elicitation.md): drawing out configuration details during a conversation
