# Trends

## Protocol abuse

Transport-layer exfiltration has moved up the stack. Raw TCP and ICMP
tunnelling, the traditional red team favourites, are increasingly detected.
Modern approaches:

DNS-over-HTTPS and DNS-over-TLS encrypt DNS queries, making DNS tunnelling
harder to detect. The query volume and subdomain entropy patterns that
betray classic DNS tunnelling are harder to spot when the traffic is
encrypted and goes to a legitimate DoH resolver.

QUIC, HTTP/3, and WebSockets are designed to defeat network surveillance.
They are encrypted end-to-end, establish connections rapidly, and carry
application-layer data in ways that are difficult to inspect. Firewalls
that cannot decrypt QUIC traffic see only encrypted UDP.

Legitimate SaaS APIs are the most reliable exfiltration channel because
they require no special tooling, generate no unusual protocol traffic, and
are already whitelisted by every enterprise firewall.

## Living-off-cloud exfiltration

Attackers use the organisation's own infrastructure and approved SaaS tools
to move data out:

- Cloud sync tools (Rclone, the Dropbox client, OneDrive) are whitelisted
  and trusted; redirecting them to an attacker-controlled account is
  indistinguishable from normal sync activity
- S3, OneDrive, and Google Drive are approved destinations; a GetObject
  or download API call to these services does not trigger a firewall alert
- Backup pipelines that copy data to external storage are a persistent
  exfiltration channel: the "backup" runs on schedule, and the attacker
  receives a copy

The result is that the firewall is guarding the front door while data
leaves through the organisation's own approved courier.

## Low-and-slow exfiltration

Bulk exfiltration is detectable by volume. Low-and-slow exfiltration
blends data movement into normal business traffic:

- Chunking into small transfers spread over days or weeks
- Matching upload/download timing to business hours
- Using SaaS API calls that match normal user interaction patterns
- Staging data in compressed, encrypted form before transfer, so the
  content is opaque even if the transfer is logged

Modern red teams exfiltrate in ways that mimic business processes rather
than malware beacons.

## Covert channels in normal systems

Any platform that moves data can be used as an exfiltration channel:

- Collaboration tools: Slack and Teams support file transfers and webhook
  integrations; a bot in a shared channel can receive exfiltrated data
- Git repositories: files committed to a public or attacker-controlled
  repository; git history is rarely monitored for content
- Logs and telemetry: application logs shipped to an external SIEM or
  monitoring service contain whatever the application writes to them
- Email: large attachments to external addresses blend into normal business
  email traffic in the absence of DLP

## What detection looks like now

Effective exfiltration detection requires behavioural baselines rather than
signature matching. The questions are:

- Is this user or application sending more data than normal?
- Is data going to a destination this identity has not used before?
- Does the volume or timing match normal business activity?
- Is a sync tool uploading to a different account than usual?

None of these questions can be answered without a baseline. Organisations
that have not established normal behaviour for users, applications, and
cloud resources cannot detect deviations from it.
