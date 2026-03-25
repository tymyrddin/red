# Cloud-native attack patterns

Some attack techniques only exist because the target is cloud-native. Serverless execution,
event-driven architectures, managed Kubernetes, and native data transfer operations create
attack surface that has no equivalent in traditional infrastructure. The techniques in this
note exploit properties of the cloud model itself rather than vulnerabilities in specific
software.

## Serverless and event-driven abuse

Serverless functions are triggered by events: object uploads to storage, messages arriving
on a queue, HTTP requests, database change events, scheduled timers. Each trigger is a
potential injection point. If the data that triggers a function is attacker-controlled and
the function does not treat it as untrusted, the attacker can influence what the function
does without ever calling it directly.

The pattern is indirect: an attacker uploads a crafted file to an S3 bucket. A Lambda
function triggered by the upload processes the file. The processing step calls an external
API using credentials from the function's execution environment. If the crafted file can
influence what API endpoint the function calls or what data it sends, the attacker has
reached the external API using the function's identity, not their own.

Event-driven pipelines chain multiple functions, each triggered by the output of the
previous. An injection at any point in the chain propagates downstream. Testing requires
tracing what each function does with its input and whether that input can reach an output
that calls another service.

## Kubernetes to cloud IAM chains

Kubernetes service account tokens grant access to the Kubernetes API. In managed Kubernetes
environments (EKS, GKE, AKS), those service accounts can also be bound to cloud IAM roles
via workload identity federation. A compromised pod that can read its service account token
may be able to exchange it for a cloud provider credential.

The chain from pod to cloud account is a standard path in mature cloud environments:

1. Compromise a pod via application vulnerability or exposed service.
2. Read the service account token from the mounted filesystem.
3. Exchange the token for a cloud provider credential via the workload identity endpoint.
4. Use the cloud credential to enumerate and act on cloud resources.

The cloud permissions granted to the service account are often broader than the application
in the pod requires, because they were set at the namespace or cluster level rather than
scoped to the specific workload.

Cluster compromise also enables the reverse path: an attacker with cloud IAM credentials who
can call the managed Kubernetes API can execute commands in pods directly, bypassing
application-level controls.

## Native exfiltration via cloud operations

Data exfiltration from cloud storage does not require anomalous outbound traffic. Every cloud
provider offers native operations that move data in ways that look like routine administration.

A storage snapshot can be created and shared with an attacker-controlled account. The snapshot
transfer happens within the cloud provider's infrastructure and does not appear as outbound
network traffic. From the victim account's perspective, a snapshot was created and shared, which
is a normal administrative operation. From the attacker's perspective, a full copy of a disk
volume or database has arrived in their account.

Similarly, S3 bucket replication can be configured to continuously copy new objects to a bucket
in another account. If an attacker has the permissions to configure replication, they can
establish a persistent data collection channel that operates indefinitely and looks like a
standard cross-account backup relationship.

These operations appear in audit logs, but they appear as their legitimate operation types.
Detection requires alerting on snapshot sharing to external accounts and replication
configuration changes, not on traffic anomalies.

## Metadata service exploitation chains

The metadata service SSRF path (application SSRF reaches the instance metadata endpoint,
returns IAM credentials) is well known. Cloud providers have added protections: IMDSv2 on
AWS requires a token obtained via a PUT request before credentials are accessible, which
prevents simple HTTP redirect-based SSRF.

The protections work when correctly configured. Many deployments still use IMDSv1 for
compatibility. Misconfigured proxies that perform the PUT request on behalf of the client
enable the same credential theft under IMDSv2. Internal services that forward requests to
the metadata endpoint for legitimate reasons become an exploitation path when SSRF reaches
them.

The chain extends beyond the initial credential. Metadata credentials have a defined scope
based on the instance role. The question after obtaining metadata credentials is the same as
after any credential theft: where does this identity sit in the permission graph, and what
can it reach from here?

## Cost and resource abuse

Cloud resource abuse does not require data access. An attacker with permissions to create
compute resources can launch GPU instances, cryptomining workloads, or large-scale data
processing jobs that generate costs on the victim's account. The attacker pays nothing; the
victim's bill arrives at the end of the month.

This is relevant to red team engagements in two ways. First, cost anomalies are often
detected faster than data access anomalies, because billing alerts are configured even when
security monitoring is not. A cost spike may be the first indicator of compromise, before
any SIEM alert fires. Testing whether cost anomalies would trigger a response gives a
realistic picture of mean time to detection.

Second, resource abuse can serve as a distraction or a pressure tool. A high-cost, noisy
operation on one part of the environment can occupy incident response while a quieter
operation targets something more valuable.

## AI-assisted path discovery

The complexity of large cloud environments, with hundreds of roles, thousands of policies,
and cross-account trust relationships, makes manual attack path analysis slow. Automated
tooling that models the environment as a permission graph and traverses it to find paths
from a starting identity to a high-value target compresses that analysis significantly.

Tools like Cloudsplaining, PMapper, and Cartography model AWS IAM as a graph and identify
privilege escalation paths, cross-account paths, and resource exposure. The output is a
prioritised list of paths, not a list of policy findings, which directly answers the question
that matters: starting from this identity, what can I reach?

Defenders who want to understand their exposure can run the same analysis. The attacker who
has already run it has a map. The question for the engagement is whether the defender's map
matches the attacker's.

## Runbooks

- [S3 and object storage discovery](../runbooks/s3-discovery.md)
- [GCP project and bucket enumeration](../runbooks/gcp.md)
- [Cloud entry playbook](../playbooks/cloud-entry.md)
