# Detect cloud recon and initial access

Cloud platforms produce detailed logs. The challenge is not data availability but signal definition:
distinguishing an attacker enumerating resources from a developer who rarely logs in, or distinguishing
a credential stuffing attempt from a user who forgot their password.

Detection requires both the logs and a baseline of what normal looks like, so that deviations are
meaningful rather than noise.

## What to instrument

### AWS CloudTrail

CloudTrail logs every API call made to AWS. It is the primary source for detection in AWS environments.
Ensure it is enabled in every region, including regions you do not actively use. Attackers enumerate
unused regions specifically because CloudTrail is often not enabled there.

Key event sources for initial access detection:

- `s3.amazonaws.com`: `ListBuckets`, `GetBucketAcl`, `GetObject` from unexpected sources
- `sts.amazonaws.com`: `GetCallerIdentity` from a new IP, `AssumeRole` across accounts
- `iam.amazonaws.com`: `ListUsers`, `ListRoles`, `GetAccessKeyLastUsed`, `CreateAccessKey`
- `ec2.amazonaws.com`: `DescribeInstances`, `DescribeSecurityGroups` from unexpected sources

Enable CloudTrail Insights to detect unusual API activity patterns automatically. Insights detects
bursts of write API calls and unusual patterns in management events.

### Azure Monitor and Entra ID logs

Azure produces two relevant log streams: Azure Activity Log for control plane events (resource
creation, deletion, configuration changes) and Azure AD sign-in logs for identity events.

Entra ID (formerly Azure AD) sign-in logs are the primary source for detecting identity-based
enumeration and initial access attempts. Key signals:

- Sign-ins from Tor exit nodes or known anonymisation infrastructure
- Sign-ins from IP addresses that have never accessed the tenant before
- Multiple failed sign-ins against different accounts from the same source IP within a short window
- Sign-ins using legacy authentication protocols (visible in the `clientAppUsed` field)
- Successful sign-ins followed immediately by unusual application access patterns

The `GetCredentialType` enumeration endpoint does not produce a sign-in log entry for invalid accounts
(because no sign-in is attempted). Detect it via Azure Front Door or WAF logs on the perimeter, or by
baselining normal traffic patterns to the authentication endpoints.

### GCP Cloud Audit Logs

GCP produces Admin Activity logs (always on, cannot be disabled) and Data Access logs (must be
explicitly enabled per service).

Enable Data Access logs for Cloud Storage. Without them, object reads are not logged and bucket
enumeration by an attacker with valid credentials is invisible.

Key signals in GCP audit logs:

- `storage.buckets.list` calls from service accounts that do not normally enumerate storage
- `storage.objects.get` calls from external IP addresses (for buckets that should only be accessed
  internally)
- `iam.serviceAccountKeys.create` events (a new key being created for a service account)
- `resourcemanager.projects.list` from an identity that has not accessed the project list before

## Detection patterns

### Credential stuffing and password spraying

Credential stuffing generates a high volume of failed authentication attempts against many accounts
from a small number of source IPs. Password spraying generates a lower volume against many accounts
with a single password to avoid lockout thresholds.

Alert on: more than five authentication failures across more than three distinct accounts from a
single IP within a ten-minute window.

Calibrate the threshold against your baseline. The right number depends on your organisation's size
and the volume of legitimate helpdesk-assisted login failures.

### Enumeration of unauthenticated surfaces

S3 bucket enumeration generates HTTP requests to bucket URLs that do not exist in your environment.
These appear in S3 access logs as 403 or 404 responses for bucket names that are permutations of
your organisation's name.

Alert on: more than ten 403 or 404 responses to bucket enumeration patterns (`GET /` or
`?list-type=2`) for bucket names that start with your organisation name, within a one-hour window.

Azure tenant enumeration via `GetCredentialType` does not produce authentication logs, but it does
produce network-layer requests. If your perimeter logs include traffic to the Microsoft authentication
endpoints, look for bursts of requests from the same source IP to that endpoint.

### First-time access from new sources

Any successful authentication from a country, ASN, or IP block that has never accessed your
environment is worth reviewing. This is a high-noise signal in large organisations but a high-value
signal in small ones.

In Microsoft 365, use the "Unfamiliar sign-in properties" risk detection in Identity Protection.
In AWS, use GuardDuty's anomaly detection for credential use from unusual locations.
In GCP, use the anomaly detection in Security Command Center.

### Unusual API access patterns after authentication

Attackers who obtain valid credentials immediately enumerate: they call `ListBuckets`, `ListRoles`,
`DescribeInstances`, and `GetCallerIdentity` in rapid succession, typically within the first few
minutes of having the credential.

Alert on: more than five distinct enumeration-pattern API calls (`List*`, `Describe*`, `Get*`)
from the same identity within a two-minute window, if that identity has not made similar calls
in the past thirty days.

### Service account key creation

Creating a new access key or service account key is a common persistence mechanism. Alert immediately
on any new service account key creation event, particularly:

- A new key created for a high-privilege service account
- A new key created outside normal working hours
- A new key created immediately after a first-time authentication from a new source

## Responding to signals

Detection signals from cloud recon and initial access attempts are most useful when they trigger
scoped investigation rather than immediate blocking. Blocking all authentication from a new country
will affect legitimate users travelling. Alerting and investigating gives you the information to
respond proportionately.

When an alert fires, establish: what did the identity access, what did it change, and is there any
indication that the initial credential acquisition was legitimate? If access was obtained through
credential stuffing or from an unexpected source, rotate the credential, revoke active sessions, and
review what was accessed in the window between first access and detection.