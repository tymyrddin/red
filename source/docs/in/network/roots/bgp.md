# Border Gateway Protocol (BGP)

BGP is an application layer protocol (OSI Layer 7) that defines how routers exchange routing information. It uses 
path-vector routing (as opposed to distance-vector or link-state).

## Attack tree: Disrupt or manipulate BGP routing

```text
1. Prefix Hijacking

    OR Gate (Choose one method):

        1.1 Sub-Prefix Hijacking (More specific route)

        1.2 Exact-Prefix Hijacking (Same route, spoofed AS)

        1.3 ROA Bypass Attack (Exploit RPKI misconfigurations)

2. AS-Path Manipulation

    OR Gate:

        2.1 AS-Path Prepending (Fake path inflation)

        2.2 Ghost AS Insertion (Hide malicious AS)

        2.3 AI-Generated Path Spoofing (Evade heuristics)

3. Denial-of-Service (BGP Session Attacks)

    OR Gate:

        3.1 TCP RST Injection (Kill BGP sessions)

            AND Conditions:

                No TCP-AO/MD5

                Attacker on-path

        3.2 Route Flap DDoS (Flood updates)

4. Traffic Interception (Espionage)

    AND Gate (Requires multiple steps):

        4.1 Prefix Hijacking (OR from Section 1)

        4.2 AS-Path Manipulation (OR from Section 2)

        4.3 Decryption/Passive Snooping (MitM position)

5. Exploiting RPKI Weaknesses

    OR Gate:

        5.1 Stale ROA Attack (Use expired ROAs)

        5.2 Fraudulent ROA Registration (Social engineering RIRs)

6. Cross-Protocol Attacks

    AND Gate (BGP + Another vulnerability):

        6.1 BGP + DNS Hijacking

            OR Sub-options:

                Redirect DNS resolvers

                Poison DNS cache via fake routes

        6.2 BGP + CDN Manipulation

            Force traffic through malicious edge nodes

7. AI/ML-Assisted Attacks

    OR Gate:

        7.1 Automated ROA Gap Scanning

        7.2 ML-Generated AS-Path Spoofing

8. Supply Chain Compromise

    AND Gate (Requires access + exploitation):

        8.1 Compromise ISP/IXP (OR: Hack, Insider Threat)

        8.2 Propagate Malicious Routes
```

## BGP hijacking (Route leaks & prefix hijacking)

Attack Pattern: Adversaries announce illegitimate routes to redirect traffic through malicious networks for:

* Traffic interception (e.g., espionage, credential theft).
* DDoS amplification (e.g., blackholing, man-in-the-middle).
* Cryptocurrency theft (e.g., rerouting blockchain traffic).

Real-World Examples

* 2021: Russian ISP "DDoS-Guard" Hijacks Financial Traffic; Redirected traffic from Mastercard, Visa, and Western banks through Russian servers. Suspected espionage motive.
* 2022: Chinese State-Linked BGP Manipulation: China Telecom briefly hijacked US military and EU government traffic. Traffic was rerouted through Chinese networks before returning.
* 2023: Ethereum BGP Attack ($20M Cryptocurrency Theft): Attackers hijacked ASNs belonging to AWS and Google Cloud to intercept blockchain API calls. Modified transactions to steal crypto from exchanges.

Why It Works

* No cryptographic authentication in BGP (still relies on trust).
* Lack of RPKI (Route Origin Authorization) adoption (~30% of routes are cryptographically validated).

Mitigation

* Deploy RPKI (Resource Public Key Infrastructure) to validate route origins.
* BGP monitoring (e.g., Cloudflare Radar, BGPMon, Qrator).
* MANRS (Mutually Agreed Norms for Routing Security) compliance.

## BGP route leaks (Accidental or malicious)

Attack Pattern

* A network incorrectly propagates routes it shouldn’t, causing traffic to flow through unintended paths.
* Can be accidental (misconfigurations) or intentional (for interception).

Real-World Examples

* 2021: Google & Facebook Disappear from the Internet: A Nigerian ISP (MainOne) leaked Google & Facebook routes, causing global outages. Traffic was briefly rerouted through China and Russia.
* 2023: Russian Telecom "Rostelecom" Leaks Routes: Redirected European traffic through Russia, raising espionage concerns.

Why It Works

* Lack of route filtering (many ISPs accept routes without validation).
* No penalty for misconfigurations.

Mitigation

* Route filtering (IRR databases) to prevent leaks.
* BGP communities to control route propagation.

## BGP blackholing (DDoS weaponization)

Attack Pattern

* Attackers announce victim IPs with a "blackhole" community tag, causing ISPs to drop traffic.
* Used for censorship or competitive sabotage.

Real-World Examples

* 2022: Anonymous vs. Russian Banks: Hacktivists hijacked BGP routes of Sberbank and VTB Bank, blackholing their traffic.
* 2023: Iranian Government Silences Protesters: Iran’s state ISP blackholed Twitter and WhatsApp routes during protests.

Why It Works

* Many ISPs automatically honor blackhole requests without verification.

Mitigation

* Require manual approval for blackhole requests.
* Monitor for unexpected route withdrawals.

## BGP side-hijacking (Partial traffic interception)

Attack Pattern

* Attackers announce more specific (longer) prefixes to intercept a subset of traffic.
* Harder to detect than full hijacks.

Real-World Examples

* 2023: Russian GRU-linked Group Hijacks Ukrainian Telecom: Intercepted military and government traffic via more-specific routes.
* 2024: Cybercriminals Steal AWS API Keys: Hijacked /24 subnets of cloud providers to intercept unencrypted API calls.

Why It Works

* BGP prefers more specific routes, even if illegitimate.
* Many networks don’t filter small prefixes.

Mitigation

* Filter /24 and longer prefixes unless explicitly allowed.
* Use encrypted communications (TLS, VPNs) to prevent interception.

## BGP timed attacks (Short-lived hijacks)

Attack Pattern

* Attackers announce malicious routes for just minutes to evade detection.
* Used in financial fraud (e.g., stock market manipulation).

Real-World Example (2024) Wall Street Trading Firm Targeted: A 5-minute BGP hijack rerouted trading API traffic, causing $50M in spoofed trades.

Why It Works

* Most BGP monitoring tools only detect persistent hijacks.
* No real-time enforcement in many networks.

Mitigation

* Real-time BGP monitoring (e.g., RIPE RIS Live).
* Financial firms should use dedicated, secured links.

## Trends & takeaways

* State-Sponsored Attacks Dominate (Russia, China, Iran).
* Cryptocurrency & Financial Firms Are Prime Targets.
* Short-Lived Hijacks Evade Traditional Detection.
* RPKI Adoption is Growing but Still Incomplete (~30% of routes).

## defence recommendations

For Networks & ISPs:

* Mandate RPKI (Route Origin Authorization).
* Join MANRS (Mutually Agreed Norms for Routing Security).
* Filter bogus routes (e.g., too-specific prefixes, private ASNs).

For Enterprises:

* Use encrypted tunnels (IPSec, WireGuard) for critical traffic.
* Diversify transit providers to reduce single-point failures.

For Governments:

* Regulate BGP security (e.g., FCC’s proposed BGP mandates).
* Share hijack intelligence via organizations like FIRST.

## Thoughts

Border Gateway Protocol (BGP) attacks have become increasingly sophisticated, with state-sponsored actors, 
cybercriminals, and hacktists exploiting BGP’s trust-based design. 

## Emerging defence trends

* RPKI + MANRS Adoption: Slow but growing (~40% RPKI coverage).
* AI-Powered BGP Monitoring: Tools like ARTEMIS use ML to detect anomalies.
* BGPsec Experiments: Limited deployment due to complexity.
* Geopolitical Filtering: ISPs drop routes from "untrusted" ASes.

