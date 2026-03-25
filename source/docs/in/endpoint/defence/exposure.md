# Reducing endpoint attack surface

Endpoint attack surface reduction works at three levels: limiting what can execute, limiting what can be harvested, and limiting how far stolen credentials can travel. Controls at each level are independent; a failure at one does not make the others irrelevant.

## Execution controls

Attack Surface Reduction rules in Microsoft Defender for Endpoint block the most commonly abused execution paths without requiring a full application allowlist. Key rules to enforce in block mode:

- Block Office applications from creating child processes (prevents macro-spawned shells).
- Block executable content from email clients and webmail (prevents HTML smuggling payloads from executing directly from downloads).
- Block credential stealing from LSASS (prevents Mimikatz and comsvcs MiniDump approaches).
- Use advanced protection against ransomware (behavioural heuristic against mass file modification).
- Block process creations from PSExec and WMI commands (reduces lateral movement options).

Application control through Windows Defender Application Control (WDAC) or AppLocker restricts execution to signed, trusted binaries. WDAC is more tamper-resistant than AppLocker and enforced at the kernel level. A policy that allows only Microsoft-signed binaries and the organisation's managed software significantly raises the cost of LOLBin abuse by eliminating the unsigned payload stage, though it does not eliminate execution through signed LOLBins themselves.

Macro execution policy should block all macros in documents downloaded from the internet (which is the default from Microsoft 365 Applications version 2203 onward). Macros from trusted locations and signed macros from trusted publishers should be the only permitted categories. Audit mode should be enabled before switching to block mode to identify legitimate macro use.

## Credential and token protection

Windows Credential Guard virtualises NTLM hashes and Kerberos tickets into a separate security context that LSASS cannot be directly read from by processes running in the normal OS context. This defeats Mimikatz sekurlsa and comsvcs MiniDump approaches that read the LSASS process directly. Credential Guard requires UEFI Secure Boot and virtualisation-based security.

WDigest authentication should be disabled. On Windows 8.1 and Server 2012 R2 and later it is disabled by default, but the registry key can be modified by an attacker with sufficient privileges to re-enable cleartext credential caching.

Conditional access policies in Entra ID should require compliant device status for any access to sensitive resources. A device that has been compromised and unenrolled from MDM, or that fails health checks, should lose access to cloud resources regardless of the validity of the credential presented.

## Browser hardening

Enterprise browser policies should disable installation of extensions from outside the approved list. Chrome and Edge support extension allowlisting through administrative templates. Extensions that request permissions to read all site data (`<all_urls>` or `*://*/*`) should require explicit approval.

HSTS enforcement and certificate pinning for internal web applications prevents TLS stripping attacks. Browser-in-the-browser attacks that spoof authentication dialogs are mitigated by ensuring all authentication flows use the system browser rather than embedded WebViews.

## MFA and session controls

Phishing-resistant MFA (hardware security keys or passkeys) replaces push notifications and OTP codes, which are vulnerable to real-time phishing and push notification fatigue attacks respectively. FIDO2 authenticators are bound to the origin, so credentials cannot be submitted to a phishing site even if the user visits one.

Session lifetime limits and continuous access evaluation reduce the window during which stolen tokens are valid. Conditional access policies that re-evaluate access on signals such as unfamiliar location, new device, or suspicious activity patterns can revoke sessions during an active attack rather than waiting for the token to expire.
