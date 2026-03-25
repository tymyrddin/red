# Runbook: Azure AD tenant enumeration

Azure Active Directory tenants expose a significant amount of configuration and identity information without
requiring authentication. The tenant structure, federation settings, and in many configurations the existence
of individual user accounts are all reachable from public endpoints. This runbook covers enumeration from
outside the tenant before any credential is obtained.

## Objective

Map the target's Azure AD tenant: its configuration, federation status, and the user accounts that exist
within it. Identify the authentication controls in place and any paths that weaken them.

## Prerequisites

- Target domain name.
- `curl` or a REST client.
- AADInternals or TokenTactics for extended enumeration (optional).
- Python with `requests` library for scripted enumeration.

## Phase 1: Tenant identification

Retrieve the OpenID Connect discovery document. This is publicly accessible for any tenant and requires no
authentication:

```bash
curl -s "https://login.microsoftonline.com/TARGET.COM/.well-known/openid-configuration" | python3 -m json.tool
```

Key fields in the response:

- `token_endpoint`: contains the tenant ID in the URL (`/TENANT-ID/oauth2/v2.0/token`)
- `issuer`: confirms the tenant identifier
- `authorization_endpoint`: reveals whether the tenant uses a custom domain or the default
  `onmicrosoft.com` domain

Record the tenant ID. It is stable, used across all Azure services, and needed for subsequent enumeration.

Check whether the tenant federates to another identity provider. If `authorization_endpoint` redirects
through a custom identity provider, the organisation's authentication is handled externally, and the
external provider's security posture matters as much as Azure's:

```bash
curl -s "https://login.microsoftonline.com/TARGET.COM/FederationMetadata/2007-06/FederationMetadata.xml"
```

A successful response means ADFS or another federation service is in use.

## Phase 2: User enumeration

The `GetCredentialType` endpoint reveals whether a given email address corresponds to a valid user account
in the tenant. The response differs depending on whether the account exists:

```bash
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username": "user@target.com"}' | python3 -m json.tool
```

`IfExistsResult: 0` means the account exists. `IfExistsResult: 1` means it does not.

This can be scripted against a list of candidate usernames generated from the identity graph:

```python
import requests, json

endpoint = "https://login.microsoftonline.com/common/GetCredentialType"
headers = {"Content-Type": "application/json"}
candidates = ["firstname.lastname@target.com", "f.lastname@target.com"]

for username in candidates:
    resp = requests.post(endpoint, headers=headers, json={"Username": username})
    result = resp.json().get("IfExistsResult")
    if result == 0:
        print(f"EXISTS: {username}")
```

Note: some tenants are configured to return `0` for all addresses (preventing enumeration), and some
return `5` for federated accounts. The exact response depends on tenant configuration, so calibrate
against a known-good and known-invalid address first.

## Phase 3: Authentication control assessment

Identify what authentication controls are in place before attempting any credential use.

Test whether the tenant enforces MFA at the tenant level or whether MFA is conditional:

```bash
# Attempt authentication with a known-invalid password to observe the challenge flow
curl -s -X POST "https://login.microsoftonline.com/TARGET.COM/oauth2/v2.0/token" \
  -d "grant_type=password&username=user@target.com&password=invalid&client_id=CLIENT_ID&scope=openid"
```

The error response reveals whether MFA is enforced (`AADSTS50076`), whether the account is locked
(`AADSTS50053`), or whether the credential was simply wrong (`AADSTS50126`). Each error code is a
data point about the authentication configuration.

Check for legacy authentication protocols. Some tenants still permit Basic Auth against Exchange Online,
IMAP, POP3, and SMTP. Legacy authentication bypasses conditional access policies and MFA:

```bash
curl -s --user "user@target.com:password" \
  "https://outlook.office365.com/EWS/Exchange.asmx" \
  -H "Content-Type: text/xml"
```

If the request returns an Exchange response rather than an authentication error, legacy authentication
is enabled and conditional access does not apply to this path.

## Phase 4: Azure Blob and storage enumeration

Enumerate storage accounts associated with the tenant.

Storage account names follow a predictable pattern based on the organisation name. Use the same
permutation approach as S3 discovery, but against Azure endpoints:

```bash
# Check existence of a storage account
curl -s -o /dev/null -w "%{http_code}" \
  "https://STORAGEACCOUNTNAME.blob.core.windows.net/?comp=list"
```

A `200` or `403` response means the storage account exists. `404` means it does not.

For accounts that exist, check whether any containers are publicly accessible:

```bash
curl -s "https://STORAGEACCOUNTNAME.blob.core.windows.net/CONTAINERNAME?restype=container&comp=list"
```

## Phase 5: Azure service enumeration via Shodan and Censys

Search for Azure-hosted services belonging to the organisation that may not be linked from public
documentation:

```
org:"Target Organisation" ssl:"target.com" port:443
```

Look specifically for:
- Management interfaces running on non-standard paths
- Development and staging environments with hostnames not in the main DNS
- Azure App Services on `*.azurewebsites.net` that expose internal applications
- Azure Functions on `*.azurewebsites.net` that accept unauthenticated requests
- Azure API Management instances that expose backend APIs directly

## Output

- Tenant ID and federation configuration.
- Confirmed valid user accounts from enumeration.
- Authentication controls observed: MFA enforcement, conditional access, legacy auth status.
- Storage accounts and containers with access control status.
- Azure-hosted services identified via passive sources and Shodan.

## Playbooks

- [Cloud initial access](../playbooks/cloud-entry.md)