# CI/CD pipeline attacks

A CI/CD pipeline is effectively root access as a service. It runs arbitrary code, has
credentials to every environment it deploys to, can modify the codebase, and typically has
weaker monitoring than production. An attacker who controls a pipeline step controls
everything the pipeline touches.

The shift in modern cloud attacks is to target build systems before production. Pipeline
compromise often grants broader access than a direct production compromise, because the
pipeline is trusted by multiple environments simultaneously.

## Why pipelines are high-value targets

Pipelines operate with credentials their workloads need to deploy: write access to container
registries, permission to update cloud functions and services, secrets for database connections
and third-party APIs, and sometimes administrative access to the cloud account itself.

These credentials are typically broader than any single application's credentials because the
pipeline serves multiple services and environments. A deployment role that can update any
Lambda function in the account can be used to insert a payload into any deployed function,
not just the one the pipeline was intended for.

Pipelines also run on infrastructure that is less scrutinised than application infrastructure.
Alerting rules written for production traffic do not always cover build runners. Build logs
may not be forwarded to the SIEM. Access to pipeline configuration is often granted to a
wider set of developers than access to production infrastructure, on the assumption that
pipeline configuration is lower risk.

## Attack vectors

Dependency poisoning is the easiest pipeline entry. A build that installs packages from a
public registry without pinned versions or integrity verification fetches the current version
of each dependency at build time. Injecting a malicious version of a depended-upon package,
or publishing a package whose name matches an internal package the organisation uses
(dependency confusion), causes the build to execute attacker-controlled code in the pipeline
environment. That code runs with the pipeline's credentials.

Secrets in build logs occur when build steps echo environment variables, print debug output,
or fail in a way that dumps the process environment. Secrets passed as environment variables
to build steps appear in the log if the step is verbose. This is a common finding in
pipelines that were configured quickly and never reviewed.

Compromised runners happen when the build runner itself is accessible or misconfigured. A
self-hosted runner with weak access controls can be reached by pull requests from forked
repositories if the pipeline is configured to run on external contributions. The runner's
filesystem persists between jobs if not isolated, allowing a malicious job to read secrets
left by a prior job.

Deployment step tampering is the highest-impact vector. In a pipeline where the deployment
step configuration is stored in the repository, an attacker with write access to the
repository can modify the deployment step to execute arbitrary code with pipeline credentials
during the next build. This does not require access to the pipeline infrastructure; it
requires only a pull request that modifies the pipeline configuration file.

## What pipeline compromise enables

A compromised pipeline provides access to every secret the pipeline uses, every environment
it deploys to, and every system it has credentials to reach. In practice this means the
attacker can deploy modified code to production, exfiltrate secrets, modify infrastructure
configuration, and establish persistence within any environment the pipeline touches, all
using credentials that are expected to perform these operations.

The forensic footprint is minimal. Build logs capture what ran but not necessarily what the
code did. If the malicious step is removed before the next audit, the evidence that it
executed may not survive the log retention period.

Testing pipeline security should start from the question: if I could execute one build step,
what would I have access to and what could I deploy?

## Runbooks

- [Cloud entry playbook](../playbooks/cloud-entry.md)
- [SaaS integration mapping](../runbooks/saas-mapping.md)
