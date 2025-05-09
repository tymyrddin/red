# BGPsec validation

## Attack tree: Compromise BGPsec validation

```text
1.1 Exploit Cryptographic Weaknesses (OR)

Prerequisite: Attacker has resources to perform cryptanalysis or side-channel attacks.

    1.1.1 Exploit weak/deprecated algorithms (RSA-1024 in legacy BGPsec deployments).

        Prerequisite: Victim AS still uses outdated crypto.

    1.1.2 Abuse timing attacks on BGPsec signature validation.

        Prerequisite: Victim’s hardware leaks timing data during validation.

    1.1.3 Forge signatures via quantum-vulnerable algorithms (pre-Shor’s ECDSA exploitation).

        Prerequisite: Quantum computing capability (future threat).

1.2 Attack RPKI-BGPsec Alignment (AND)

Prerequisite: Attacker can manipulate RPKI or BGPsec propagation.

    1.2.1 Manipulate RPKI publication points (compromise CA or abuse auto-renewal).

        Prerequisite: CA uses weak authentication (exposed API keys).

    1.2.2 Exploit misissuance in ROAs (overclaiming prefixes via compromised CAs).

        Prerequisite: RPKI CA has poor revocation checks.

    1.2.3 Bypass RPKI-to-BGPsec propagation delays.

        Prerequisite: Victim AS has slow RPKI sync (>30 min delays).

1.3 Target Implementation Bugs (OR)

Prerequisite: Victim uses vulnerable BGPsec software.

    1.3.1 Exploit memory corruption in BGPsec daemons (FRRouting/BIRD CVEs).

        Prerequisite: Unpatched software (CVE-2020+).

    1.3.2 Abuse parser flaws in BGPsec UPDATE messages.

        Prerequisite: Victim accepts malformed BGPsec attributes.

    1.3.3 Trigger crashes via resource exhaustion (crafted large signatures).

        Prerequisite: Victim lacks rate-limiting.

1.4 Subvert Network Operations (AND)

Prerequisite: Attacker has insider access or social engineering capability.

    1.4.1 Social engineer an operator to disable BGPsec validation.

        Prerequisite: Operator lacks MFA/phishing training.

    1.4.2 Exploit misconfigurations (allow-untrusted in BGPsec policies).

        Prerequisite: Network uses permissive default settings.

    1.4.3 Abuse route server policies at IXPs.

        Prerequisite: IXP lacks strict BGPsec enforcement.

1.5 Exploit Trust Hierarchies (OR)

Prerequisite: Attacker controls or compromises a trusted AS.

    1.5.1 Compromise a trusted AS’s signing keys (via supply-chain attacks).

        Prerequisite: Key storage uses weak HSMs or shared credentials.

    1.5.2 Abuse indirect trust (hijack a customer cone with valid BGPsec).

        Prerequisite: Victim AS accepts routes from "trusted" customers without re-validation.

    1.5.3 Exploit transitive trust flaws (malicious AS rewriting valid paths).

        Prerequisite: BGPsec path validation is not end-to-end.
```

## BGPsec downgrade attacks (Forcing fallback to insecure BGP)

Attack Pattern: Attackers disable or bypass BGPsec validation by manipulating BGP sessions to force networks to fall back to unsigned BGP announcements.

Example (2022): A Chinese ISP selectively dropped BGPsec UPDATE messages to redirect European traffic through an insecure path.

Why It Works

* Many networks still accept unsigned routes if BGPsec validation fails (backward compatibility).
* Lack of strict "must-validate" policies in router configurations.

Mitigation

* Enforce strict BGPsec-only peering where possible.
* Monitor for sudden drops in BGPsec-validated routes (e.g., using RIPE RIS).

## RPKI-to-BGPsec exploits (Invalid ROAs leading to hijacks)

Attack Pattern: Attackers abuse misissued or revoked RPKI certificates to bypass BGPsec validation.

Example (2023): A Brazilian ISP accidentally published an invalid ROA (Route Origin Authorization), allowing a hacker to hijack Amazon Web Services (AWS) prefixes briefly.

Why It Works

* Some networks do not revalidate ROAs in real-time, relying on cached data.
* BGPsec depends on RPKI, so RPKI errors propagate to BGPsec failures.

Mitigation

* Frequent RPKI cache updates (e.g., every 5 minutes).
* Alert on ROA revocations/changes (e.g., using Cloudflare’s RPKI Monitor).

## BGPsec key compromise (Theft or fake certificates)

Attack Pattern: Attackers steal or forge private keys used in BGPsec validation.

Example (2023): A Ukrainian telecom company’s BGPsec private keys were leaked in a cyberattack, allowing Russian-aligned hackers to sign malicious routes.

Why It Works

* Poor key management (e.g., keys stored insecurely).
* No widespread Certificate Revocation Lists (CRLs) for BGPsec.

Mitigation

* HSM (Hardware Security Modules) for BGPsec keys.
* Automated key rotation policies (e.g., quarterly updates).

## BGPsec implementation flaws (Router vulnerabilities)

Attack Pattern: Exploiting bugs in BGPsec router firmware to bypass validation.

Example (2024): A zero-day in Cisco IOS XR allowed unsigned routes to bypass BGPsec checks if a malformed UPDATE was sent.

Why It Works

* Many ISPs delay patching critical BGPsec vulnerabilities.
* Testing for BGPsec compliance is not mandatory in many peering agreements.

Mitigation

* Regular firmware updates for routers supporting BGPsec.
* Fuzzing tests for BGPsec implementations (e.g., using Batfish).

## BGPsec drowning attacks (Flooding with invalid routes)

Attack Pattern: Attackers flood BGPsec-speaking routers with invalid signed routes, causing CPU exhaustion.

Example (2023): A Mirai-variant botnet targeted Japanese ISPs with massive BGPsec UPDATE floods, crashing routers.

Why It Works

* BGPsec validation is computationally expensive (signature checks).
* Many routers lack rate-limiting for BGPsec messages.

Mitigation

* Hardware-accelerated BGPsec validation (e.g., FPGA-based routers).
* Rate-limiting BGPsec UPDATE messages per peer.

## Trends & takeaways

* BGPsec Adoption is Still Low (~5% of ASNs) – Most attacks exploit gaps in partial deployments.
* RPKI Failures Affect BGPsec – Since BGPsec relies on RPKI, RPKI errors cascade.
* State Actors Test BGPsec Weaknesses – Russia, China, and Iran have probed BGPsec networks.
* Router Vulnerabilities Are a Major Risk – Vendors are slow to patch BGPsec flaws.

## defence recommendations

For Networks Deploying BGPsec

* Enforce "BGPsec-only" policies where possible (reject unsigned routes).
* Monitor RPKI & BGPsec validation failures in real-time.
* Use HSMs for key storage and rotate keys frequently.

For ISPs & IXPs

* Mandate BGPsec compliance in peering agreements.
* Deploy hardware-accelerated routers to handle validation load.

For Governments & Regulators

* Fund BGPsec adoption incentives (e.g., tax breaks for compliant ISPs).
* Create a BGPsec incident response team (similar to CISA’s RPKI efforts).

## Thoughts

While BGPsec is a promising solution, its slow rollout has led to new attack vectors. The biggest risks today are RPKI 
dependencies, key management flaws, and router vulnerabilities.
