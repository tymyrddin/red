# Challenge design principles

To create an effective cloud hacking CTF, challenges should progress from basic reconnaissance to full-scale cloud 
compromise, teaching practical skills at each level. Below is an expanded breakdown of difficulty tiers, including 
learning objectives, real-world parallels, and defensive takeaways.

## Beginner (Easy) – "The Cloud Tourist"

Goal: Introduce fundamental cloud concepts and tools.

Example challenge:

"Find the open S3 bucket named flag-bucket-{randomID} and retrieve flag.txt."

Skills taught:

* Basic enumeration – Using awscli, gobuster, or manual inspection.
* Public bucket identification – Recognising misconfigured storage.
* Cloud provider UI navigation – AWS Console, GCP Storage Explorer.

Real-world parallel:

* Bug Bounty Scenario: Finding exposed S3 buckets with sensitive data.
* Defensive Takeaway: Always set BlockPublicAccess and audit bucket policies.

Tools needed:

```bash
aws s3 ls s3://flag-bucket-123 --no-sign-request  # Check open bucket
curl https://flag-bucket-123.s3.amazonaws.com/flag.txt  # Direct fetch
```

## Intermediate (Realistic) – "The Privilege Escalator"

Goal: Teach IAM exploitation, lateral movement, and OSINT.

Example challenge:

"A Lambda function has overprivileged IAM rights. Steal its keys and escalate to an EC2 instance."

Skills taught:

* AWS CLI & SDK Usage – Extracting Lambda env vars, assuming roles.
* IAM Privilege Escalation – Exploiting iam:PassRole, sts:AssumeRole.
* OSINT for Cloud Credentials – Searching GitHub, logs, metadata.

Real-world parallel:

* Penetration Test Finding: Lambda with AdministratorAccess leaking keys.

* Defensive Takeaway: Principle of Least Privilege (PoLP) for Lambda roles.

Exploit chain:

* Dump Lambda env vars (via RCE or /proc/environ).
* Find AWS keys → aws sts get-caller-identity.
* Escalate via iam:PassRole → aws ec2 describe-instances.

## Advanced (Red Team) – "The Cloud Kingdom Takedown"

Goal: Simulate full cloud compromise (AWS/GCP/Azure).

Example challenge:

"A GCP service account key was leaked. Use it to compromise the entire organisation."

Skills taught:

* Cloud Pivoting – Moving from one service to another.
* OAuth & API Abuse – Escalating via iam.serviceAccounts.getAccessToken.
* Lateral Movement – From Cloud Functions to Compute to BigQuery.

Real-world parallel:

* APT Attack: Stolen service account keys leading to cloud takeover.
* Defensive Takeaway: Disable key creation, enforce VPC-SC, monitor IAM anomalies.

Exploit chain:

* Leaked key → gcloud auth activate-service-account.
* Enumerate resources → gcloud projects list.
* Privilege escalation → Abuse roles/owner on a project.
* Data exfiltration → Dump BigQuery datasets.

## Challenge progression flow

"A good cloud CTF doesn’t just teach hacking, it forces players to think like defenders. Every challenge should scream: ‘This is why you should’ve patched this.’"

| Level	        | Attack path	              | Defensive lesson          |
|---------------|---------------------------|---------------------------|
| Beginner	     | Find open S3 bucket	      | Secure public storage     |
| Intermediate	 | Lambda → EC2 takeover	    | Least privilege for IAM   |
| Advanced	     | SA key → Org-wide breach	 | Service account hardening |


