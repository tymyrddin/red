# Cloud vulnerabilities for challenges

I am not thinking big, hahaha. From easy to advanced:

## Storage & access misconfigurations

* S3/GCP Bucket Enumeration (Open listings, sensitive data leaks)
* Azure Blob Storage "Public Read" Exploits
* Presigned URL Abuse (Time-limited but guessable URLs)

## IAM & privilege escalation

* Overprivileged Lambda Roles (Exfiltrate env vars)
* AWS AssumeRole Hijacking (Via stolen STS tokens)
* GCP Service Account Key Leaks

## Serverless & API exploits

* Lambda RCE via Malicious Event Inputs
* API Gateway Misconfigs (CORS, Auth Bypass)
* GraphQL Introspection → Data Dump

## CI/CD pipeline hacks

* GitHub Actions Token Theft
* Jenkins/GitLab RCE via Unauthenticated Endpoints
* ArgoCD SSRF → Cluster Takeover

## Container & Kubernetes attacks

* Docker Socket Exposure → Host Escape
* K8s Dashboard No-Auth → Pod Exec
* ETCD Unauthenticated Access → Cluster Secrets

## Advanced cloud-native exploits

* AWS SSM Session Manager Abuse
* GCP Cloud Build Privilege Escalation
* Azure Automation Account RCE