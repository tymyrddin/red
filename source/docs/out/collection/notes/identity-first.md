# Identity-first collection

The most efficient path to sensitive data in a modern organisation is through
a valid identity, not through an exploit. Every SaaS application, cloud console,
and internal tool has access control tied to an identity provider. Control the
identity, and you control what it can see.

## Why attackers prefer this path

There is no exploit to patch. A valid token presenting valid credentials to
a legitimate API endpoint generates no alert. The attacker is, from the
system's perspective, the user. Detection requires understanding what normal
behaviour looks like and spotting deviations, which most organisations cannot
do reliably.

## Entry points

### Helpdesk and password reset abuse

Helpdesk processes that reset credentials based on identity verification (a
name, employee number, or callback to a phone number) are social engineering
targets. The attacker impersonates the user, passes the verification, and
receives a fresh credential or MFA bypass.

The full technique is covered in the phishing and social engineering sections.
From a collection perspective, the output is: valid credentials for a target
account.

### MFA fatigue

Push-notification MFA can be bypassed by sending repeated approval requests
until the user approves out of frustration or confusion. After approval, the
attacker's session is authenticated with full MFA.

### OAuth application consent

A malicious OAuth application can be registered to request access to the
target's cloud tenant. When a user with sufficient permissions grants consent,
the application receives tokens that persist beyond the user's session and
are not revoked by password changes.

### SSO and federated identity abuse

If a subsidiary, partner, or external identity provider is federated with
the target tenant, compromising the external entity yields access to the
primary tenant. The persistence lives in the trust relationship, not in
any credential.

## What identity access reaches

Once a valid identity is controlled:

- Microsoft 365 / SharePoint: all documents the user can access, plus mail
- AWS / Azure: resources the identity's IAM permissions cover
- GitHub / GitLab: repositories, secrets, pipeline configurations
- HR and finance SaaS: payroll, personnel records, financial data
- Internal tools: Confluence, Jira, internal wikis, runbooks

In environments with weak role separation, a single standard user account
may have read access to most of the organisation's sensitive data through
shared drives, SharePoint permissions inherited from department groups, and
SaaS applications granted to all staff.

## Collection via delegated permissions

After gaining identity access, collection uses the platform's own APIs:

```python
# Microsoft Graph: enumerate files accessible to the compromised identity
import requests

headers = {'Authorization': f'Bearer {access_token}'}

# list top-level SharePoint sites
r = requests.get('https://graph.microsoft.com/v1.0/sites?search=*', headers=headers)
for site in r.json().get('value', []):
    print(site['displayName'], site['webUrl'])

# list drives on a site
r = requests.get(f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives", headers=headers)

# search for files across all drives
r = requests.get(
    "https://graph.microsoft.com/v1.0/me/drive/root/search(q='password')",
    headers=headers)
for item in r.json().get('value', []):
    print(item['name'], item['webUrl'])
```

```python
# AWS: enumerate S3 buckets and download objects
import boto3

s3 = boto3.client('s3',
    aws_access_key_id=KEY,
    aws_secret_access_key=SECRET,
    aws_session_token=SESSION_TOKEN)  # if using temporary credentials

for bucket in s3.list_buckets()['Buckets']:
    print(bucket['Name'])
    try:
        for obj in s3.list_objects_v2(Bucket=bucket['Name']).get('Contents', []):
            print(' ', obj['Key'], obj['Size'])
    except Exception as e:
        print(' access denied:', e)
```

## Privilege escalation within identity plane

A standard user identity may allow escalation to administrative access through:

- Misconfigured role inheritance in Azure AD or AWS IAM
- Forgotten admin accounts with shared credentials
- Service account credentials readable by the compromised identity
- OAuth applications with more permissions than the authorising user intended

Once admin or global admin access is obtained, the entire tenant's data
is accessible.

## Operational notes

- Pace API calls to match normal user activity; bulk downloads trigger DLP
  alerts in environments that have them
- Prefer accessing documents through the platform's own web interface where
  possible; it is indistinguishable from normal user behaviour
- Avoid downloading files to disk on the compromised host; use the API to
  forward directly to attacker-controlled infrastructure
- Tokens stolen from one device work from any device; exfiltrate the token
  and operate from a clean environment rather than the compromised host
