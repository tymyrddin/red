# Abusing misconfigurations

Misconfiguration is a big reason why systems are exploited in on-premises environments and with cloud resources.

Whether it is Software as a Service (SaaS), Platform as a Service (PaaS), or Infrastructure as a Service (IaaS), securing cloud asset configurations can be simple or very complex. 
The more sophisticated the platform, the more difficult it may be to secure the platform, and when moving into PaaS or IaaS, complexities can be huge, and mistakes are made more easily. The bigger the energy-saving promise, the bigger the entropy.

## Identity and access management

* IAM consists of the users, groups, roles, and permissions of users and assets within a cloud environment. 
* Permissions are explicit grants of access given to a user, group, or asset.
* Roles are designed to roll up permissions so that they can be used across different users, groups, or assets. 
* They are built so that a specific task can be performed. Roles may nest other roles under them to perform a task.
* A best practice is to have roles assigned to groups and to place users in the groups, for role-based access control (RBAC). 
* Applications and systems may also have permissions, including permissions to access other services, to create and destroy files within a data store, and to update certain cloud configurations.

## Federation attacks

These attacks do not exploit vulnerabilities in federated authentication products, but abuse legitimate functions after a local network or admin account compromise. 

### Federation

Federation takes an identity provider and uses it as the authentication source for an environment. It uses technologies like OAuth, SAML, or OpenID to act as identity providers that can perform authentication outside an environment, then return data about the authenticated party so the platform itself can handle authorisation. This is secured with shared secrets, such as certificates. If those secrets are compromised, then the security of the federation is compromised.

Some services allow more than one federated authentication source or multiple keys.

### Local network to cloud attack

1. Compromise on-premises components of a federated SSO infrastructure and steal the credential or private key that is used to sign Security Assertion Markup Language (SAML) tokens. 
2. Forge trusted authentication tokens to access cloud resources.
    
### Escalation

Gaining sufficient administrative privileges within a cloud tenant to add a malicious certificate trust relationship for forging SAML tokens:

1. Leverage a compromised global administrator account to assign credentials to cloud application service principals (identities for cloud applications that allow the applications to be invoked to access other cloud resources).
2. Invoke the application's credentials for automated access to cloud resources (often email in particular) that would otherwise be difficult for the actors to access or would more easily be noticed as suspicious.

## Object storage attacks

Object storage is one of the most abused cloud components and are often due to misconfigurations.

1. Identify storage that is accessible from an unauthenticated point of view
2. identify storage that is accessible from an authenticated view

## Container attacks

Docker and Kubernetes share some common attack patterns (such as kernel exploits), but Kubernetes works off of kubelets, users, pods, secrets, and more, which have unique attack vectors.

### Containerisation

Docker is typically only used for small numbers of containers on a specific host and Docker Swarm is used for orchestration when there are a small number of systems with a small number of services. 

Kubernetes is better for systems that require orchestration across many nodes, and offers enterprise-level scalability and resiliency. 

### Attack

1. Break out of containerised system
2. Leverage container resources to further your access to other systems, or to the hosting system

## Remediation

Cloud service misconfigurations are the most common cloud vulnerability (misconfigured S3 Buckets). The most famous case was that of the Capital One data leak which led to the compromise of the data of roughly 100 million Americans and 6 million Canadians. The most common cloud server misconfigurations are:

* Improper permissions
* Not encrypting the data and differentiation between private and public data.

## Resources

* [Okta](https://www.okta.com/identity-101/what-is-federated-identity)
* [AWS federation](https://aws.amazon.com/identity/federation)
* [Azure federation](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed)
* [Google cloud federation](https://cloud.google.com/architecture/identity/federating-gcp-with-active-directory-introduction)
* [OAuth](https://oauth.net/2/)
* [SAML](https://auth0.com/blog/how-saml-authentication-works/)
* [OpenID](https://openid.net/)
* [S3 Leaks](https://github.com/nagwww/s3-leaks)
* [Container Breakouts – Part 1: Access to root directory of the Host](https://blog.nody.cc/posts/container-breakouts-part1/)
* [Container Breakouts – Part 2: Privileged Container](https://blog.nody.cc/posts/container-breakouts-part2/)
* [Container Breakouts – Part 3: Docker Socket](https://blog.nody.cc/posts/container-breakouts-part3/)
* [Snyk: Kernel exploits](https://snyk.io/blog/kernel-privilege-escalation/)
* [Threat matrix for Kubernetes](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
* [Attacking and Defending Kubernetes: Bust-A-Kube – Episode 1](https://www.inguardians.com/attacking-and-defending-kubernetes-bust-a-kube-episode-1/blog/)

