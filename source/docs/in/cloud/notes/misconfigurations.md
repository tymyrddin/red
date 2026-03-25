# Cloud misconfigurations

The most visible form of cloud misconfiguration is the publicly accessible storage bucket.
It still happens, and it is still worth checking. But it is no longer the main event. The
attack surface that consistently produces access in modern cloud environments is identity:
over-permissioned roles, trust relationships with missing conditions, federated identities
that grant more access than intended, and services that communicate with each other without
any authentication requirement.

## IAM as the real attack surface

Cloud IAM policies define what identities can do. A policy that grants more than necessary,
or one that contains a wildcard where a specific resource ARN should be, is a misconfiguration
whether or not anyone has exploited it. The gap between what a role is used for and what it is
permitted to do is the attack surface.

Common patterns that produce exploitable misconfigurations:

An IAM role scoped to read one S3 bucket but granted `s3:*` on `*`. A Lambda execution role
that has `iam:PassRole` and `ec2:RunInstances`, allowing privilege escalation without touching
any compute. A service account with `roles/owner` because someone needed to debug something
and the permission was never narrowed. A CI/CD pipeline role with write access to production
and no conditions requiring the source to be the main branch.

None of these require a vulnerability to exploit. They require an attacker to notice that the
identity has slightly too much access and then use it.

## Federation trust misconfigurations

Federated authentication takes an external identity provider and grants it the ability to
produce tokens that the cloud environment trusts. The trust relationship is secured by a
shared secret, typically a certificate or signing key. A misconfigured trust relationship can
allow an attacker who controls the right input to produce tokens that are accepted as
legitimate by the cloud environment.

The most impactful variant is a trust relationship with overly broad subject matching: a policy
that accepts any subject from the identity provider, rather than constraining it to specific
workloads or repositories. An OIDC trust relationship for a GitHub Actions role that accepts
`repo:*` instead of `repo:org/specific-repo:ref:refs/heads/main` allows any repository in the
organisation, or in some configurations any public repository, to assume that role.

## Service-to-service implicit trust

Inside many cloud environments, services trust each other without verifying identity. An
internal API is callable from anything on the same VPC. A message queue delivers to any
subscriber. An event trigger calls any function configured to receive it. This is a design
choice that is convenient during development and becomes a misconfiguration when the
perimeter assumption breaks.

When an attacker gains access to any workload inside the trust boundary, they inherit the
implicit trust that workload enjoys. The question then becomes not "can I authenticate to this
service" but "which workloads can I reach from here, and what can they do?"

## Object storage misconfigurations

Public storage is the obvious case. Less obvious: storage that is not public but is accessible
to any authenticated user in the cloud provider's ecosystem. AWS has a specific configuration
that prevents public access while still allowing any authenticated AWS user to access the
bucket. A bucket set to "authenticated users can read" is not public by the provider's
definition but is reachable by anyone with an AWS account.

Misconfigured bucket policies that grant access to `*` with a condition on the requesting
service may be more permissive than intended if the condition is incorrectly scoped. A policy
intended for one Lambda function that matches on service principal rather than a specific
ARN applies to every Lambda function in every account.

## Runbooks

- [S3 and object storage discovery](../runbooks/s3-discovery.md)
- [Azure AD tenant enumeration](../runbooks/azure-tenant.md)
- [GCP project and bucket enumeration](../runbooks/gcp.md)
