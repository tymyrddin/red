# Resource Public Key Infrastructure (RPKI)

## Attack tree: Compromise RPKI validation

```text
1. Compromise RPKI Validation (OR-gate)

    1.1. Exploit RPKI Validator Vulnerabilities

        Prerequisite: Unpatched validator software (Routinator, Fort, OctoRPKI).

        Sub-attacks:

            1.1.1. Exploit memory corruption (CVE-2022-XXX).

            1.1.2. BGP hijack bypass via validator misconfiguration (OR-gate).

    1.2. Manipulate RPKI Cache (AND-gate)

        Prerequisite: Access to RPKI cache server (rsync/http).

        1.2.1. Poison cache with invalid ROAs (requires compromised CA or MITM).

        1.2.2. Delay propagation of valid ROAs (DoS on RPKI repository).

2. Attack RPKI Certificate Authorities (OR-gate)

    2.1. Compromise CA Private Keys

        Prerequisite: Weak key management (leaked HSMs, side-channel attacks).

        2.1.1. Extract keys via cloud HSM vulnerabilities (CVE-2021-XXX).

        2.1.2. Social engineering CA operators (OR-gate).

    2.2. Exploit CA Policy Weaknesses

        2.2.1. Obtain fraudulent ROAs via CA misissuance (accidental over-claiming).

        2.2.2. Exploit delayed revocation (ROA remains valid after compromise).

3. BGP Hijack Despite RPKI (OR-gate)

    3.1. Exploit RPKI Non-Enforcement

        Prerequisite: Victim AS does not enforce RPKI (ROV=0).

        3.1.1. Hijack non-RPKI-covered prefixes (OR-gate).

        3.1.2. Exploit "unknown" validation state (ROA missing).

    3.2. Launch Subprefix Hijack (AND-gate)

        Prerequisite: Legitimate ROA exists but lacks maxLength restriction.

        3.2.1. Announce more specific prefix (/24 under a /22 ROA).

        3.2.2. Ensure victim AS does not filter invalid announcements.

4. Attack RPKI Repository Infrastructure (OR-gate)

    4.1. Exploit Repository Sync Vulnerabilities

        4.1.1. Delay ROA updates via rsync/HTTP DoS (slowloris).

        4.1.2. Serve stale RPKI data (requires MITM or compromised repo).

    4.2. Target RPKI TAL (Trust Anchor Locator) Distribution

        Prerequisite: Access to TAL update mechanism.

        4.2.1. Distribute malicious TAL (via compromised package mirrors).

5. Exploit RPKI Protocol Weaknesses (OR-gate)

    5.1. Manipulate ASPA (AS Provider Authorization) Records

        Prerequisite: ASPA adoption is partial.

        5.1.1. Forge ASPA to allow path spoofing (requires compromised AS).

    5.2. Abuse RPKI Time-to-Live (TTL) Gaps

        5.2.1. Launch transient hijacks during TTL expiration.
```

## Attack tree: Combined RPKI + BGPsec attack tree

OR-gates = Only one sub-attack needed (exploit RPKI or BGPsec).

AND-gates = Requires multiple steps (poison RPKI and spoof BGPsec).

```text
1. Bypass RPKI Origin Validation via BGPsec Exploits (OR-gate)

    1.1. Exploit BGPsec Non-Enforcement (AND-gate)

        Prerequisite: Victim AS enforces RPKI but not BGPsec (common in partial deployments).

        1.1.1. Hijack RPKI-validated prefix with invalid BGPsec path (OR-gate).

            Sub-attack: Spoof AS_PATH signatures (if BGPsec is poorly implemented).

        1.1.2. Exploit "RPKI-Valid + BGPsec-Invalid" routes (leverage inconsistent validation).

    1.2. Abuse BGPsec Key Compromise to Forge Valid Routes (AND-gate)

        Prerequisite: Compromise BGPsec private keys (via HSM breach or weak key generation).

        1.2.1. Sign malicious AS_PATH updates for RPKI-covered prefixes.

        1.2.2. Combine with RPKI time-delay attacks (slow revocation).

2. Exploit RPKI + BGPsec Trust Chain Collisions (OR-gate)

    2.1. Compromise Shared Trust Anchors (AND-gate)

        Prerequisite: Overlapping CA trust (RPKI TA also used for BGPsec).

        2.1.1. Revoke RPKI ROAs but keep BGPsec keys valid (or vice versa).

        2.1.2. Forge cross-protocol validity conflicts (RPKI says valid, BGPsec says invalid).

    2.2. Attack the TAL + BGPsec Trust Distribution (OR-gate)

        Prerequisite: Access to trust anchor distribution channels (NIST TALs).

        2.2.1. Distribute malicious TALs + BGPsec trust anchors.

        2.2.2. Delay updates to one protocol while exploiting the other.

3. Combine RPKI Cache Poisoning with BGPsec Path Spoofing (AND-gate)

    3.1. Poison RPKI Repository to Hide BGPsec Attacks

        Prerequisite: MITM access to RPKI rsync/HTTP repositories.

        3.1.1. Delay ROA revocations while executing BGPsec path hijacks.

        3.1.2. Inject stale RPKI data to mask BGPsec-invalid routes.

    3.2. Exploit BGPsec’s Slow Rollout (OR-gate)

        Prerequisite: Partial BGPsec adoption (only some ASes validate).

        3.2.1. Route leaks through non-BGPsec ASes (bypassing signed paths).

        3.2.2. Use RPKI-valid origins with unsigned AS_PATHs.

4. Exploit Cryptographic Weaknesses in Both Protocols (OR-gate)

    4.1. Precompute Attacks on Shared Algorithms (AND-gate)

        Prerequisite: RPKI/BGPsec use the same weak crypto (ECDSA with biased nonces).

        4.1.1. Reuse compromised RPKI keys to sign BGPsec updates.

        4.1.2. Exploit hash collisions in certificate chains.

    4.2. Post-Quantum Readiness Gaps (OR-gate)

        Prerequisite: No PQ migration in RPKI/BGPsec (still using RSA/ECDSA).

        4.2.1. Harvest now, decrypt later (with future quantum computers).

        4.2.2. Forge signatures via Shor’s algorithm (theoretical but looming).

5. Cross-Protocol Transient Attacks (AND-gate)

    5.1. Exploit TTL Mismatches Between RPKI and BGPsec

        Prerequisite: RPKI cache TTL ≠ BGPsec update frequency.

        5.1.1. Launch short-lived hijacks during validation gaps.

    5.2. Abuse BGPsec’s "Valid-But-Unverifiable" States

        Prerequisite: BGPsec allows unverifiable paths if RPKI is valid.

        5.2.1. Combine with RPKI maxLength misconfigurations.
```

## RPKI-Invalid hijacking (Exploiting unprotected routes)

Attack Pattern

* Attackers hijack IP prefixes not covered by RPKI ROAs (Route Origin Authorizations).
* Targets networks that lack RPKI signing or misconfigure ROAs.

Real-World Examples

* 2021: Russian ISP Hijacks Financial Prefixes: Exploited missing RPKI records for European bank IPs, rerouting traffic for interception.
* 2023: Cryptocurrency Exchange DNS Hijack: Attackers hijacked RPKI-unprotected AWS prefixes to steal API credentials.

Why It Works

* ~30% of routes still lack RPKI (MANRS 2024 data).
* Many networks don’t enforce RPKI validation strictly (accept "NotFound" routes).

Mitigation

* Sign all critical prefixes with ROAs (max-length protection).
* Enforce "Valid Only" policies on routers (e.g., Junos validation-group).

## RPKI Time-to-Live (TTL) attacks (Cache poisoning)

Attack Pattern

* Manipulate RPKI cache timing to delay revocation checks or serve stale data.
* Exploits RPKI validator sync delays (typically 15–60 mins).

Real-World Example (2022)

* Chinese hackers delayed ROA revocations during a Taiwan telecom attack, extending hijack windows.

Why It Works

* RPKI relies on periodic cache updates (not real-time).
* Some validators ignore TTLs due to performance tuning.

Mitigation

* Reduce TTLs to ≤ 5 minutes for critical ROAs.
* Use multiple RPKI validators (e.g., Routinator + rpki-client).

## ROA Overclaiming (Authorizing too-broad prefixes)

Attack Pattern

* Create overly permissive ROAs (e.g., authorizing /16 when only /24s are used).
* Allows attackers to hijack sub-prefixes without triggering invalidation.

Real-World Example (2023)

* A Brazilian ISP accidentally authorized a /19 ROA, enabling a competitor to hijack unused /24s.

Why It Works

* No automated checks for overclaiming (manual audits required).
* Operators often set maxLength too high for convenience.

Mitigation

* Strict maxLength policies (e.g., exact prefix length or +1).
* Tools like RPKI Monitor (Cloudflare) to detect overclaims.

## RPKI CA compromise (fake or revoked certificates)

Attack Pattern

* Attackers compromise RPKI CAs (e.g., via stolen credentials) to issue malicious ROAs.

Real-World Example (2024)

* An Iranian APT group breached a Middle Eastern RIR’s RPKI portal, issuing fraudulent ROAs for government IP blocks.

Why It Works

* Weak CA access controls (e.g., shared credentials, no MFA).
* Slow revocation propagation (up to 1 hour in some cases).

Mitigation

* Enforce MFA for RPKI CA portals.
* Monitor CT logs for unauthorized ROAs (e.g., RIPE NCC’s RPKI Dashboard).

## Ghost prefix attacks (Exploiting RPKI "Unknown" state)

Attack Pattern

* Announce RPKI-unknown prefixes (no ROA exists) to bypass filtering.
* Relies on networks not enforcing "NotFound" routes strictly.

Real-World Example (2023)

* A cybercrime group hijacked RPKI-unknown AWS prefixes to host phishing sites.

Why It Works

* Many networks default to "accept" for Unknown routes.
* RPKI coverage gaps persist (especially in cloud/IPv6).

Mitigation

* Treat "NotFound" as "Invalid" in BGP policies.
* Aggressively sign all customer prefixes.

## RPKI drowning (Validator DoS)

Attack Pattern

* Flood RPKI validators with fake certificates or queries, crashing them.
* Creates a window for hijacks while validators recover.

Real-World Example (2024)

* A Mirai-variant botnet targeted Cloudflare’s RPKI validators, causing temporary validation outages.

Why It Works

* Many validators lack rate-limiting.
* RPKI infrastructure is centralized (few major public validators).

Mitigation

* Run local validators (e.g., Routinator) + cache results.
* Anycast validator deployments for resilience.

## Trends & takeaways

* State Actors Target RPKI Gaps – Russia, China, Iran exploit partial adoption.
* Human Errors > Protocol Flaws – Misconfigured ROAs cause most incidents.
* Cloud & IPv6 Are Weak Spots – Lower RPKI adoption vs. legacy IPv4.
* Attacks Shift to "Soft" Exploits – Cache/CA attacks replace brute force.

## Defence recommendations

For Network Operators

* Sign all prefixes with ROAs (use maxLength carefully).
* Enforce "Valid Only" BGP policies (reject Unknown/Invalid).
* Monitor RPKI changes (e.g., RIPE RPKI Explorer).

For RIRs/CAs

* Mandate MFA for RPKI management portals.
* Accelerate revocation propagation (push-notify validators).

For Governments

* Fund RPKI adoption in critical infrastructure.
* Share threat intel on RPKI CA breaches (for example via FIRST).

## Thoughts

RPKI is effective when fully deployed, but partial adoption creates exploitable gaps. Strict ROA management, CA security, and real-time monitoring are essential to prevent hijacks.

## Emerging threats

* Post-quantum risks (future threat to RPKI’s cryptographic foundations).
* AI-assisted attack automation (probing for weak ROAs at scale).
* Cross-protocol attacks (combining RPKI weaknesses with BGPsec flaws).

## Emerging defence

* Strict cross-protocol validation (reject routes unless both RPKI+BGPsec valid).
* Faster revocation sync (real-time RPKI + BGPsec updates).
* Post-quantum crypto migration (switching to Falcon/Dilithium).

