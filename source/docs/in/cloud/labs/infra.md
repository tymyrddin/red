# Infrastructure requirements

To host cloud challenges:

* Cloud Provider Accounts (AWS/GCP/Azure) – Free tiers work for basic labs.
* Terraform/Ansible – Automate deployment of vulnerable setups.
* Containerisation (Docker/Kubernetes) – For isolated, ephemeral challenge environments.
* Monitoring & rate limiting – Prevent abuse (e.g., AWS GuardDuty, custom scripts).
* Flag Validation System – Auto-check exploit success (e.g., stolen secrets, RCE).

This I will combine with [AWS Security: Protecting Your Cloud Kingdom from Barbarians (and Dave)](https://blue.tymyrddin.dev/docs/dev/devsecops/aws/),
[Azure Security: Defending Microsoft’s Mansion from Uninvited Guests](https://blue.tymyrddin.dev/docs/dev/devsecops/azure/), 
[GCP Security: Keeping Google’s Playground from turning into a Hackfest](https://blue.tymyrddin.dev/docs/dev/devsecops/gcp/),
and [On-Prem “Cloud” Security: Playing Sysadmin on Nightmare Mode](https://blue.tymyrddin.dev/docs/dev/devsecops/on-prem/).

First set up secure pipelines for a small dockerised app, then introduce vulnerabilities.