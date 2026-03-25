# Credential and session theft

The endpoint's value in a modern attack is largely its credential store: the cached passwords, SSO tokens, browser cookies, and cloud access tokens that give access to everything the user can reach. Stealing this material is often faster, quieter, and more durable than maintaining a persistent backdoor on the device itself. The session goes with the attacker; the device is left undisturbed.

## Windows credential material

LSASS (Local Security Authority Subsystem Service) holds the most concentrated source of credential material on a Windows system. It caches NTLM hashes and Kerberos tickets for logged-in users, and on older or misconfigured systems may hold cleartext passwords via WDigest. Dumping LSASS with Mimikatz or its successors requires SeDebugPrivilege and generates significant EDR telemetry; modern approaches avoid direct process access.

Alternatives to direct LSASS dumping:

The Windows Task Manager dump (technically legitimate, used by EDR to dump its own processes) can be redirected to LSASS by changing the target PID. This abuses a signed Microsoft binary. `comsvcs.dll`'s MiniDump export provides the same capability from `rundll32.exe`. Both approaches are now monitored by most EDR platforms but remain effective against weaker deployments.

The SAM database and the LSA secrets stored in the registry contain local account hashes and service account credentials. These can be extracted using Volume Shadow Copy to copy the locked registry hives offline, then parsed with `secretsdump.py` from Impacket.

Kerberos tickets in memory can be extracted and imported elsewhere (pass-the-ticket) without needing to know the underlying password. A TGT extracted with Rubeus provides the same access as the user's credentials for the ticket's validity period.

## Browser credential stores

Browsers store saved passwords, cookies, and session tokens on disk in formats that are decryptable with the user's OS credentials. Chrome and Edge store credentials in an SQLite database encrypted with DPAPI, which is decryptable from the user's session without prompting for credentials. Firefox stores credentials in a different format but is similarly accessible.

Session cookies for web applications and SaaS platforms are stored in the browser's cookie database. Extracting these cookies and importing them into an attacker-controlled browser instance bypasses authentication entirely, regardless of MFA. The session is already authenticated; the attacker simply hijacks the session.

Tools such as SharpChrome and LaZagne automate browser credential extraction. The resulting cookies can be imported using browser extensions or via direct HTTP requests with the extracted `Cookie` header.

## Cloud and SaaS token theft

Cloud CLI tools cache access tokens on disk. The AWS CLI stores credentials in `~/.aws/credentials`; the Azure CLI caches tokens in `~/.azure/`; `kubectl` stores cluster credentials in `~/.kube/config`. Any of these files on a compromised endpoint provide direct API access to the associated cloud resources, usually without requiring MFA because the token itself already represents a completed authentication.

OAuth tokens stored in application data directories follow the same pattern. A developer's machine is particularly valuable because it holds tokens for CI/CD systems, code repositories, cloud accounts, and internal tooling simultaneously. Compromising a developer's endpoint can provide more access than compromising a server.

## SSO and identity provider abuse

Single sign-on implementations store authentication state in ways that are accessible from the endpoint. Microsoft Entra ID joined devices hold Primary Refresh Tokens (PRTs) that can be used to obtain access tokens for any resource the user has access to, without re-authentication. The PRT is stored in LSASS and extractable with tools such as ROADtools and AADInternals.

Pass-the-PRT allows an attacker who has extracted the token to authenticate as the user to any Entra ID-protected resource from a different device. Since the PRT represents the user's authentication state rather than a specific application session, it provides broader access than a single application's access token.

SAML tokens, once issued, are similarly portable. If a SAML response can be captured or an assertion can be forged (through a compromised identity provider or a signature wrapping attack), it provides access to any service provider in the federation.

## The pivot pattern

The practical value of credential and token theft is that it moves the attacker's activity off the monitored endpoint. Once tokens are extracted, the attacker operates from infrastructure that the organisation's EDR does not monitor, using access that looks like the legitimate user. The endpoint can be abandoned. Detection now depends on user and entity behaviour analytics in the identity provider and cloud control plane, not on the EDR that was the initial barrier.
