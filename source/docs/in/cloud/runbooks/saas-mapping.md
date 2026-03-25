# Runbook: SaaS integration mapping

Organisations accumulate SaaS tools and integrations over time. Each authorised integration is a trust
relationship: the SaaS application has been granted access to the organisation's data, often with permissions
that were set at initial configuration and never reviewed. Mapping these integrations reveals access paths
that bypass the core identity perimeter entirely.

## Objective

Identify the SaaS tools in use at the target organisation. Determine what access each has been granted.
Find integration tokens, API keys, or OAuth credentials exposed in public sources.

## Prerequisites

- Target organisation name and domain.
- LinkedIn access for employee enumeration.
- GitHub access for repository search.
- Shodan for passive infrastructure enumeration.
- Knowledge of common SaaS OAuth patterns.

## Phase 1: SaaS tool identification

The most reliable sources for SaaS tool identification are job postings, LinkedIn employee profiles,
and DNS TXT records.

### Job postings

Current and archived job postings for technical, operations, and administrative roles list required
tool experience. A posting for a Sales Operations Analyst reveals the CRM. A posting for an IT Support
Engineer lists the ITSM platform, MDM, and endpoint management tools. A posting for a Developer lists
the CI/CD platform, monitoring stack, and collaboration tools.

Archive job postings from the main job board, LinkedIn, and the organisation's careers page. Cross-
reference across multiple postings to build the complete picture.

### DNS TXT records

Service verification TXT records confirm which SaaS providers have been given access to send on behalf
of the domain or to verify domain ownership:

```bash
dig +short TXT target.com
```

Common patterns to look for:

```
v=spf1 include:sendgrid.net ...          # SendGrid for email delivery
v=spf1 include:salesforce.com ...        # Salesforce
google-site-verification=...             # Google Workspace or Google Search Console
MS=...                                   # Microsoft 365 domain verification
docusign=...                             # DocuSign
stripe-verification=...                  # Stripe
atlassian-domain-verification=...        # Atlassian Cloud
```

### LinkedIn and employee profiles

LinkedIn profiles listing "Skills & Endorsements" for specific tools confirm adoption. Groups joined
by employees, courses completed, and certifications held all reveal the tooling in use. Infrastructure
engineers and DevOps staff often list the specific platforms they manage.

## Phase 2: Integration token exposure

Search GitHub and public repositories for integration credentials.

Each SaaS tool has characteristic credential formats. Common patterns to search for:

```bash
# Slack tokens
grep -r "xoxb-" .          # Bot tokens
grep -r "xoxp-" .          # User tokens
grep -r "xoxs-" .          # Workspace session tokens

# Stripe
grep -r "sk_live_" .
grep -r "pk_live_" .

# SendGrid
grep -r "SG\." .

# Twilio
grep -r "TWILIO_AUTH_TOKEN" .
grep -r "AC[a-z0-9]{32}" .

# HubSpot
grep -r "hapikey=" .

# Salesforce
grep -r "client_secret" . --include="*.yml" --include="*.json"

# GitHub tokens
grep -r "ghp_" .
grep -r "github_pat_" .
```

Use TruffleHog for systematic pattern matching against all repository content including history:

```bash
trufflehog github --org=TargetOrg --only-verified
```

## Phase 3: OAuth application enumeration

OAuth applications granted consent to the organisation's Microsoft 365 or Google Workspace tenant
represent persistent access that survives password resets and persists beyond the authorising user's
session.

For Microsoft 365, the consent framework allows any user (or all users, depending on tenant policy)
to grant third-party applications access to their data. If user consent is permitted for non-admin
applications, enumerate what permissions employees are likely to have granted. Common over-provisioned
applications include:

- Productivity tools requesting `Mail.Read` or `Mail.ReadWrite`
- Note-taking and CRM tools requesting `Files.ReadWrite.All`
- Communication tools requesting `Calendars.ReadWrite`

The consent grant runbook in the social engineering section covers this from the attacker side.
From a recon perspective, the goal is to understand which permissions model the tenant uses and
whether user consent is permitted.

For Google Workspace, the Google OAuth scope documentation describes what each scope grants. The
most valuable scopes for an attacker are `https://www.googleapis.com/auth/drive`,
`https://www.googleapis.com/auth/gmail.readonly`, and
`https://www.googleapis.com/auth/admin.directory.user.readonly`.

## Phase 4: Exposed Slack workspaces

Slack workspaces with open self-join links or publicly accessible archives represent a direct
intelligence source. Some Slack workspaces allow anyone with an invite link to join, and old invite
links sometimes appear in public GitHub repositories or support documentation.

Search GitHub for Slack invite links:

```bash
grep -r "slack.com/join/shared_invite" .
```

If an invite link is found and still valid, the workspace may be joinable without approval. Even
read-only access to a Slack workspace reveals: internal tooling names from channel names and bot
integrations, personnel names and roles from channel membership, ongoing projects from active
discussions, and sometimes credentials shared informally in messages.

## Phase 5: ITSM and ticketing system exposure

ITSM platforms (ServiceNow, Jira, Zendesk) sometimes have portal pages that are accessible without
authentication or with self-registration. These portals can expose:

- Customer and employee names from ticket references
- Internal system names from ticket subjects and descriptions
- Technology stack details from incident reports
- Current projects and initiatives from request queues

Check whether the organisation's support portal allows self-registration or unauthenticated browsing
of public-facing content.

## Output

- SaaS tool inventory with source of discovery for each.
- Integration credentials found in public repositories.
- OAuth application consent model for Microsoft 365 and Google Workspace tenants.
- Slack workspace access status.
- ITSM portal accessibility and content visible without authentication.

## Playbooks

- [Cloud initial access](../playbooks/cloud-entry.md)