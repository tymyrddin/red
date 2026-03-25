# Identity and account attacks

Cloud environments have no perimeter in the traditional sense. What they have is identity:
credentials, tokens, roles, and trust relationships that determine who can do what. Attacking
a cloud environment means attacking the identity graph, not the network topology.

The shift is significant. An attacker does not need to pivot through subnets or escalate
through local administrator. They need a valid identity with slightly too much access and
the knowledge of what that access can reach.

## Token theft

Credentials in cloud environments are frequently available to workloads that need them to
function. The mechanisms that deliver credentials to workloads are the same mechanisms that
an attacker exploits once inside.

The instance metadata service is the most consistent source. Any process running on a cloud
virtual machine or container that can reach the metadata endpoint can retrieve the instance
role credentials without authentication. An SSRF vulnerability in a web application running
on EC2 is directly convertible to IAM credentials:

```bash
# AWS metadata service (IMDSv1 - no token required)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata service
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

CI/CD pipelines expose credentials as environment variables. Build logs frequently capture
those variables in plain text when a command echoes its environment. Pull request pipelines
triggered by external contributors may expose secrets to code the contributor controls.
Deployment scripts committed to repositories often contain access keys that were intended
to be temporary.

Workload identity tokens are shorter-lived than static keys but are renewed automatically,
which means they are continuously available to any process that can reach the right endpoint.
A Kubernetes pod that can read its service account token file and reach the cloud provider's
token exchange endpoint has access to whatever IAM role the pod's service account is bound to.

## Identity graph traversal

The value of a stolen identity depends entirely on what that identity can reach and assume.
The first task after obtaining any credential is to understand its position in the identity
graph: what can this role do directly, and what other roles or identities can it create,
modify, or assume?

In AWS, a role with `sts:AssumeRole` permissions can assume other roles if the trust policy
of the target role permits it. A role with `iam:PassRole` and the ability to create Lambda
functions or EC2 instances can attach any passable role to a new resource, then retrieve
credentials from that resource. A role with `iam:CreateAccessKey` can create long-lived keys
for any user.

The chain from a low-privilege role to a high-privilege outcome rarely involves a single
permission. It involves assembling several individually innocuous permissions into a sequence
that the IAM policy designer did not anticipate when assigning each one. Mapping this
requires enumerating not just what the current role can do but what resources, roles, and
services are reachable from it.

## Lateral movement via trust relationships

In traditional environments, lateral movement means moving between hosts. In cloud
environments, it means moving between identities and across trust boundaries.

A service account that has permission to create resources in a project can create a resource
with a different, more privileged service account attached. A role that can update a Lambda
function's code can replace that function's handler with code that exfiltrates the execution
environment, including the function's role credentials. A developer account that can modify
a CI/CD pipeline configuration can inject steps that capture pipeline credentials during the
next build.

Cross-account trust is a particularly powerful path. Production accounts routinely trust
roles in development or tooling accounts for deployment and monitoring purposes. Compromising
a development account with a trust relationship to production grants access to production
without ever touching the production account's credentials directly.

## Federation abuse

Federated authentication systems accept tokens from external identity providers. A federated
trust relationship that is not correctly scoped allows anyone who can produce a token the
identity provider will sign to assume the associated role.

The classic example is a GitHub Actions OIDC trust relationship with a too-broad subject
claim: configured to accept any repository rather than a specific one. An attacker who can
trigger a workflow in any repository matching the claim can assume the role and its associated
cloud permissions.

SAML federation, where an on-premises identity provider is trusted by a cloud environment,
creates a path from the on-premises network to the cloud. Compromising the SAML signing
certificate allows forging assertions for any identity, including privileged ones, without
touching cloud credentials directly.

## Runbooks

- [Azure AD tenant enumeration](../runbooks/azure-tenant.md)
- [Cloud entry playbook](../playbooks/cloud-entry.md)
