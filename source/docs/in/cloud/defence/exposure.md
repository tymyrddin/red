# Reduce cloud attack surface

Most cloud initial access exploits something that was knowable before the attack started: a public bucket,
an exposed credential, an enumerable tenant, or an integration that was granted more access than it needed.
Reducing the attack surface means systematically removing those known quantities.

## Object storage

### Audit public access settings

Every major cloud provider now offers account-level or project-level controls that block public access to
object storage regardless of per-bucket settings. These should be enabled by default on every account that
does not explicitly need to serve public content.

AWS: enable "Block Public Access" at the account level via the S3 console or:

```bash
aws s3control put-public-access-block \
  --account-id ACCOUNT-ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Azure: set the storage account's `allowBlobPublicAccess` property to `false` via policy or directly:

```bash
az storage account update \
  --name STORAGEACCOUNTNAME \
  --resource-group RESOURCEGROUP \
  --allow-blob-public-access false
```

GCP: enforce uniform bucket-level access and disable the legacy ACL system:

```bash
gsutil uniformbucketlevelaccess set on gs://BUCKET-NAME
```

### Audit existing buckets

Run a full audit of every storage account and bucket to confirm no unintended public access exists.
Many public buckets were made public deliberately for a specific use case and never reviewed again.

Use AWS Config rules, Azure Policy, and GCP Organization Policy to enforce access control standards
and alert on deviations. Treat any storage resource with public access that is not explicitly in
an approved register as a misconfiguration to be remediated.

### Secrets in repositories

Scan public GitHub and GitLab repositories belonging to the organisation and its employees for
committed credentials. Use a tool that searches commit history, not just the current branch:

```bash
trufflehog github --org=YourOrg --only-verified
```

Enable secret scanning in your GitHub organisation settings. GitHub secret scanning will alert
on known credential patterns pushed to any repository in the organisation, including private ones.

Rotate any credential that has been committed to a repository, regardless of when it was committed
and regardless of whether the repository was private at the time. Treat committed credentials as
compromised.

## Identity and access

### Disable legacy authentication

Legacy authentication protocols (Basic Auth against Exchange, IMAP, POP3, SMTP) bypass conditional
access policies and MFA. In Microsoft 365, block them via a conditional access policy:

Set condition: "Client apps: Exchange ActiveSync clients + Other clients (legacy auth)."
Set access control: "Block access."

Monitor for any legacy authentication attempts before blocking to identify affected users and
applications. Give a transition period for legitimate legacy clients (printers, scanners, old
email clients), then block unconditionally.

### Restrict OAuth user consent

By default, Microsoft 365 permits users to grant OAuth applications access to their data without
admin approval. This means any user can authorise a malicious application to read their email,
access their files, and act on their behalf.

In the Azure portal under Azure Active Directory > Enterprise Applications > Consent and permissions:
set "Users can consent to apps accessing company data on their behalf" to "No." Require admin
consent for all OAuth applications.

In Google Workspace under Security > API controls: configure which OAuth scopes users can consent
to themselves and which require admin approval. At minimum, restrict consent for sensitive scopes
including Gmail, Drive, and Admin SDK.

### Enforce MFA for all accounts

MFA should be enforced by conditional access policy, not by user-level MFA registration settings.
A conditional access policy that requires MFA for all cloud access applies regardless of whether
the individual user has set up MFA in their profile.

Include service accounts and break-glass accounts in the MFA review. Service accounts that cannot
use interactive MFA should be protected by certificate-based authentication or managed identity
rather than username and password.

### Least privilege on IAM roles

Review IAM role assignments against what is actually needed. The most common finding is that roles
were assigned with a broad permission set during initial setup and never narrowed.

AWS: use IAM Access Analyzer and AWS CloudTrail to generate least-privilege policies based on
actual access patterns over the past 90 days.

Azure: use Azure AD Access Reviews to periodically recertify role assignments. Set up regular
review cycles for privileged roles including Global Administrator, User Administrator, and
application-specific owners.

GCP: use Policy Insights and recommender API to identify overly permissive bindings.

## SaaS and integrations

### Audit OAuth applications

Review the OAuth applications that have been granted access to your Microsoft 365 and Google
Workspace tenants. Remove applications that:

- Are not in active use
- Belong to vendors whose relationship has ended
- Were authorised by users who have since left
- Request more permissions than their stated function requires

In Microsoft 365, review under Azure Active Directory > Enterprise Applications. In Google Workspace,
review under Security > API controls > Manage third-party app access.

### Restrict self-registration in SaaS tools

Review which SaaS platforms in use permit external self-registration or guest access. Slack, Notion,
Confluence, and similar collaboration tools sometimes have workspace settings that allow anyone with
a link to join, or allow users to invite external guests without approval.

Require approval for all new user invitations and guest access grants. Disable self-join links.
Audit existing guest and external accounts against the list of approved vendors and contractors.