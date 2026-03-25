# Why cloud environments are hard to test

Cloud environments present a different set of testing challenges from traditional
infrastructure. The attack surface spans identities, services, APIs, and trust relationships
rather than hosts and ports. Attack paths chain small permissions across multiple services
rather than exploiting a single vulnerability. Many of the most impactful paths leave no
anomalous signal until it is too late to matter.

## The attack surface is a graph, not a stack

Traditional infrastructure has layers: external, DMZ, internal, privileged. Lateral movement
follows network topology. The mental model is vertical: you go deeper.

Cloud environments are graphs. Identities connect to services. Services connect to APIs and
storage. Event triggers connect serverless functions to data pipelines. Trust relationships
connect accounts, projects, and external systems. The attack path is rarely vertical; it
follows edges in the identity and permission graph that no single team has a complete view of.

A complete picture of the attack surface requires mapping not just what resources exist but
which identities can reach which other identities, and what each identity can do once assumed.
That map changes every time a role is created, a policy is updated, or a new service is
provisioned. Testing a point-in-time snapshot of the graph does not guarantee the findings
are still accurate two weeks later.

## Ephemeral compute and detection gaps

Cloud workloads start and stop in seconds. A serverless function that runs for three seconds
and then terminates may not appear in any monitoring dashboard. A container that processes
a queue item and shuts down may not forward its logs before it disappears. Spot and preemptible
instances are terminated by the provider without warning.

This ephemerality is exploitable. An attacker who can trigger a short-lived workload, extract
value from it, and allow it to terminate may complete the attack within the detection pipeline's
latency window. The workload is gone before the logs are analysed. The finding appears in the
billing record, or not at all.

Testing against ephemeral environments requires validating that logging is complete before the
resource terminates, that logs are forwarded to a durable destination, and that detection rules
operate on stream data rather than waiting for batch analysis.

## Multi-cloud inconsistency

Most large organisations run workloads across multiple cloud providers and dozens of SaaS
platforms, connected by federated identity. Each provider has its own IAM model, its own
logging format, and its own set of default configurations. An assumption that is safe in AWS
may be dangerous in Azure. A permission that is benign in isolation may chain with a permission
on another platform in a way neither platform's documentation anticipates.

The inconsistency creates gaps. A security control applied to AWS resources may not exist in
the equivalent GCP service. An identity that is locked down in the corporate directory may have
a separate, less-monitored identity in a SaaS platform that was set up independently. A
privilege escalation path that crosses from one provider to another may not be visible from
either provider's audit logs.

Testing multi-cloud environments requires following the identity chain across platforms, not
just examining each platform in isolation.

## Cross-service attack chains

The most impactful cloud attack paths are chains: each step uses a permission that seems
reasonable in isolation, and together they produce an outcome no one intended. A low-privilege
role that can read from a secrets manager, trigger a Lambda function, and push to a container
registry can, in sequence, read a deployment credential, use it to trigger a build, and replace
a production container image.

No individual permission in that chain is obviously dangerous. The chain is dangerous. Finding
chains requires modelling the environment as a graph and tracing paths between the current
identity and high-value targets, not reviewing permissions policy by policy.

## Cost and resource abuse as a signal

Cryptomining and GPU abuse for AI workloads exploit the same access paths as data theft. An
attacker who can spin up compute resources can generate costs without extracting any data. This
matters for two reasons.

First, cloud cost anomalies are often the first indicator that something has gone wrong. An
unexpected spike in EC2 compute or GPU usage may be detected faster than a data access pattern.
Testing should include whether cost alerts would fire before a data exfiltration alert.

Second, resource abuse can be used to exhaust budget controls or distract attention during a
more targeted operation. A noisy cryptomining campaign on one account can consume the incident
response capacity that should be investigating a quieter data theft in another.
