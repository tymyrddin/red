# Cloud surface discovery

Before interacting with a cloud environment, map what is exposed from the outside. The cloud attack surface is
largely identity and configuration, not ports and services. Most of it is publicly enumerable without sending a
single packet to the target.

## What you are looking for

The goal at this stage is not to find a specific vulnerability. It is to understand which providers the
organisation uses, what they have exposed without intending to, and which access paths are worth pursuing.

Cloud entry points fall into a small number of categories: exposed storage with public or misconfigured access
controls, identity provider configuration that reveals tenant details or permits user enumeration, management
and API endpoints that respond to unauthenticated requests, and SaaS integrations that have been granted
excessive trust.

## Provider identification

Start without touching the target. DNS records, certificate transparency logs, and job postings answer most
provider questions.

MX records pointing to `*.protection.outlook.com` or `*.google.com` confirm the email platform. CNAME records
pointing to `*.blob.core.windows.net`, `*.s3.amazonaws.com`, or `*.storage.googleapis.com` confirm storage
use. TXT records added for service verification name the SaaS tools the organisation uses for email delivery,
monitoring, and infrastructure.

Certificate transparency logs expose the full subdomain inventory, including cloud-hosted assets:

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

Job postings for cloud engineers, DevOps, and platform roles are the most detailed public inventory of what
is running. A posting that asks for experience with a specific tool, service, or architecture is telling you
exactly what the environment contains. Archive these before they disappear.

## What passive sources reveal

Shodan and Censys index cloud infrastructure continuously. Searching by organisation name, ASN, or domain
surfaces exposed services, open ports, and sometimes full banner data that identifies versions and
configurations:

```
org:"Target Organisation" port:443
asn:AS12345 has_screenshot:true
```

GitHub and GitLab repositories associated with the organisation frequently contain configuration files,
deployment scripts, and commit history that includes infrastructure details: bucket names, account IDs,
internal hostnames, and sometimes credentials. Search the organisation name and primary domain across
public repositories, including repositories belonging to employees and contractors.

Wayback Machine archives of the target's web properties often include API documentation, legacy endpoints,
and configuration pages that have been removed but not decommissioned.

## Identity provider surface

The identity provider is the most important element to map early, because it determines what is actually
reachable and through what mechanism.

For Microsoft 365 tenants, the OpenID Connect discovery endpoint returns the tenant ID and federation
configuration without authentication:

```bash
curl https://login.microsoftonline.com/target.com/.well-known/openid-configuration
```

This reveals whether the tenant uses federated authentication (and therefore which external identity
provider is trusted), the token endpoint, and the tenant ID. The tenant ID is stable and used across
Azure services, making it useful for subsequent enumeration.

For Okta tenants, the subdomain is usually predictable (`target.okta.com`) and the existence of the
tenant is confirmed by the login page response.

For Google Workspace, workspace existence and federation status are visible from the SAML metadata
endpoint and from the MX record pattern.

## What to produce

By the end of passive cloud recon, you should have: the primary cloud provider or providers in use, the
identity platform and federation configuration, a list of internet-facing cloud services and their
approximate access control posture, any storage resources with public or misconfigured access, and any
credentials or configuration material found in public repositories.

That is enough to choose which runbooks to run next.

## Runbooks

- [S3 and object storage discovery](../runbooks/s3-discovery.md)
- [Azure AD tenant enumeration](../runbooks/azure-tenant.md)
- [GCP project and bucket enumeration](../runbooks/gcp.md)
- [SaaS integration mapping](../runbooks/saas-mapping.md)