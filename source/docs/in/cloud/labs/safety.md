#  Safety notes for cloud CTF labs

Running vulnerable cloud environments requires strict isolation and active monitoring to prevent accidental breaches 
or malicious abuse. 

## Dedicated cloud accounts (Non-prod)

Prevents accidental damage to real business resources and limits blast radius if credentials leak.

* AWS: Create a new account under AWS Organisations (no payment methods attached).
* GCP: Use a separate project with billing alerts ($0.01 threshold).
* Azure: Set up a "Test" subscription with spending caps.

Example (AWS CLI):

```bash
# Create a new AWS account for labs (via Organizations)
aws organizations create-account --email "ctf-labs@yourdomain.com" --account-name "RootMe-Cloud-CTF"
```

## Auto-destroy timers (Avoid cost leaks)

Stops forgotten labs from accumulating costs, and prevents long-term exposure of vulnerable resources.
* AWS Lambda + CloudWatch: Schedule a termination function.
* Terraform Auto-Destroy:

```
resource "null_resource" "destroy_after" {
  triggers = {
    always_run = timestamp()  # Forces destroy-after to trigger
  }

  provisioner "local-exec" {
    command = "sleep 7200 && terraform destroy -auto-approve"  # 2-hour timeout
  }
}
```

Alternative: Use AWS EventBridge to auto-terminate resources tagged CTF=true after 2 hours.

## Abuse monitoring (Block malicious activity)

CTF labs attract attackers looking to mine crypto or host malware.

* AWS GuardDuty: Enable and alert on:
    * `Cryptocurrency:EC2/BitcoinTool.B!DNS`
    * `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
* GCP Log Alerts: Monitor for:
  * `compute.instances.create` from non-trusted IPs
  * `storage.buckets.list` spikes (brute-force scanning)
* Custom Scripts: Detect abnormal CPU usage (e.g., >90% for 10 mins = auto-shutdown).

Example (AWS CLI GuardDuty Alert):

```bash
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

## Network isolation

Prevents lab compromises from spreading to other environments.

* AWS: Use a dedicated VPC with no peering/NAT.
* GCP: Enable VPC Service Controls to block exfiltration.
* Azure: Apply NSGs blocking outbound traffic except to whitelisted IPs.

Example (AWS VPC Isolation):

```
resource "aws_vpc" "ctf_isolated" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = false  # Reduce attack surface
}
```

## Credential hygiene

Leaked keys = compromised cloud org.

* Short-Lived Creds: Use AWS STS AssumeRole (max 1-hour sessions).
* GCP: Disable service account key creation (use Workload Identity).
* Azure: Require MFA for all users.

Example (GCP Hardening):

```bash
# Disable service account key creation
gcloud iam deny-policy --organization=YOUR_ORG_ID \
  --deny-all --identity='*' \
  --permissions='iam.serviceAccountKeys.create'
```

## Legal protection

CTF labs can be mistaken for real attacks.

* AWS: Submit Penetration Testing Request.
* GCP/Azure: Document lab IP ranges for abuse teams.
* Add a "This is a CTF" banner to all web interfaces.

## Checklist before launch

1. ✅  Dedicated cloud account with billing alerts
2. ✅  Terraform destroy-after timer (2-4 hours max)
3. ✅  GuardDuty/Log Monitoring enabled
4. ✅  Network isolation (no peering, egress filtering)
5. ✅  Legal/abuse team notified

