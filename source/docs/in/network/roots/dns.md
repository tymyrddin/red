# Domain Name System (DNS)

## Attack tree: Compromise DNS infrastructure or Data Exfiltration

```text
1. Exploit Protocol Weaknesses

    1.1 Cache Poisoning

        1.1.1 Exploit weak TXID entropy in DoH resolvers OR

        1.1.2 Side-channel attack on DoT implementations

        Prerequisite: AND (Attacker can intercept traffic AND resolver lacks DNSSEC)

    1.2 DDoS Amplification

        1.2.1 Abuse misconfigured DoQ resolvers OR

        1.2.2 Weaponize DNSSEC (NSEC3 walking)

        Prerequisite: AND (Open resolver available AND vulnerable payload size)

2. Attack Encrypted DNS

    2.1 Privacy Leaks

        2.1.1 Correlate DoH metadata (IP + timestamps) OR

        2.1.2 ML-based fingerprinting of encrypted traffic

    2.2 Downgrade Attacks

        2.2.1 Force fallback to plaintext DNS via TCP RST injection AND

        2.2.2 Disable ECH (Encrypted Client Hello) in DoH

3. Cloud/SaaS Exploits

    3.1 Kubernetes DNS Compromise

        3.1.1 Poison CoreDNS cache AND

        3.1.2 Bypass NetworkPolicy rules

    3.2 Serverless Abuse

        3.2.1 Lambda DNS tunneling (TXT exfiltration) OR

        3.2.2 Azure Private Resolver spoofing

4. Supply Chain Attacks

    4.1 Registrar Hijacking

        4.1.1 Steal API keys (Cloudflare, Route 53) OR

        4.1.2 Social engineer registrar support (post-GDPR WHOIS gaps)

    4.2 Subdomain Takeover

        4.2.1 Find dangling CNAME (GitHub Pages) AND

        4.2.2 Deploy malicious content

5. AI/ML-Augmented Attacks

    5.1 Evasion

        5.1.1 Poison DNS reputation models OR

        5.1.2 Generate benign-looking queries (mimic CDN traffic)

    5.2 Phishing Automation

        5.2.1 LLM-generated homograph domains AND

        5.2.2 Dynamic DNS fast-flux

6. Post-Quantum Threats

    6.1 Cryptographic Harvesting

        6.1.1 Collect ECDSA-P256 DNSSEC records AND

        6.1.2 Store for future quantum decryption

    6.2 QKD Spoofing

        6.2.1 Photon-splitting attack on QKD OR

        6.2.2 Fake QKD handshake
```

## DNS amplification DDoS attacks

Attack Pattern

* Abuse open DNS resolvers to flood targets with massive UDP response traffic (amplification factor: 50x-100x).
* Common query types: ANY, TXT, or crafted EDNS requests.

Real-World Examples

* 2021: Microsoft Azure Hit by 2.4 Tbps Attack: Used DNS reflection from misconfigured servers in Asia.
* 2023: Russian Hacktivists Target European Banks: Leveraged IoT botnets to launch DNS water torture attacks (subdomain floods).

Why It Works

* Open resolvers (~3M still exist per Censys).
* No UDP source validation (easy IP spoofing).

Mitigation

* Deploy Response Rate Limiting (RRL) on DNS servers.
* Block ANY queries at resolvers.

## DNS Cache poisoning (Intoxication)

Attack Pattern

* Corrupt DNS caches by injecting fake records (e.g., A, NS).
* Exploits weak transaction IDs or predictable ports.

Real-World Examples

* 2022: Iranian APT34 "DNSpionage": Poisoned caches of Middle Eastern ISPs to redirect govt sites to phishing pages.
* 2024: Fake AWS S3 Endpoints: Attackers hijacked s3.amazonaws.com resolutions to steal API keys.

Why It Works

* DNSSEC adoption remains low (~20% of zones).
* Legacy resolvers lack randomized ports/IDs.

Mitigation

* Enforce DNSSEC validation (e.g., Cloudflare 1.1.1.1).
* Use DNS-over-HTTPS (DoH) to prevent snooping.

## DNS tunneling (Data exfiltration)

Attack Pattern

* Encode stolen data in DNS queries/responses (e.g., longsubdomain.example.com).
* Bypasses firewalls by masquerading as "legitimate" traffic.

Real-World Examples

* 2023: North Korean Kimsuky Espionage: Exfiltrated South Korean defence docs via TXT record lookups.
* 2024: Ransomware C2 via Dynamic DNS: Used free DDNS providers (no-ip.com) for malware communications.

Why It Works

* Most tools don’t inspect DNS payloads deeply.
* Free DDNS services enable easy anonymity.

Mitigation

* Monitor for long/random subdomains (e.g., data1.data2.evil.com).
* Block known tunneling tools (e.g., Iodine, DNScat2).

## DNS hijacking (Registrar/Provider compromise)

Attack Pattern

* Steal credentials to modify NS records or registrar accounts.
* Redirect domains to attacker-controlled servers.

Real-World Examples

* 2021: "Sea Turtle" Targets IT Service Providers: Hijacked DNS for telecoms in 13 countries via stolen certs.
* 2023: Crypto Exchange Ledger Breach: Attackers altered ledger.com DNS to drain wallets.

Why It Works

* Weak MFA at registrars (e.g., email-only verification).
* Delayed DNS propagation checks.

Mitigation

* Registry Lock critical domains (e.g., Verisign’s service).
* Monitor for NS record changes (e.g., DNSTwister).

## Phantom domain attacks (Resolver exploitation)

Attack Pattern

* Flood resolvers with queries to non-existent domains, exhausting resources.
* Often paired with NXDOMAIN floods.

Real-World Examples

* 2022: AWS Route 53 Outage: Botnets queried millions of fake domains, degrading performance.
* 2024: Chinese "Great Cannon" Disrupts TLDs: Targeted .tw and .hk resolvers with junk queries.

Why It Works

* Resolvers cache negative responses poorly.
* Recursive queries amplify load.

Mitigation

* Aggressive NXDOMAIN caching (e.g., min-cache-ttl 300).
* Anycast DNS to distribute load.

## DNS rebinding (Bypass Same-Origin policy)

Attack Pattern

* Use short-TTL records to trick browsers into accessing internal IPs.
* Exploits web apps that trust client-side DNS.

Real-World Examples

* 2023: Home Router Takeovers: Hijacked 50,000+ devices via malicious JavaScript + DNS rebinding.
* 2024: SaaS Provider Breach: Attackers accessed internal APIs via rebind attacks on localhost.

Why It Works

* Many apps don’t validate Host headers.
* Default router admin panels lack CSRF protections.

Mitigation

* Block private IP resolutions at firewalls.
* Use Host header whitelisting.

## Trends & takeaways

* State Actors Dominate High-Impact Attacks (Russia, Iran, China, North Korea).
* Rise of "Water Torture" Subdomain Attacks – Harder to filter than volumetric floods.
* DNSSEC Adoption Still Lagging – Critical for cache poisoning defence.
* IoT Botnets Fuel DDoS – Mirai variants now specialize in DNS floods.

## Defence recommendations

For Network Operators

* Deploy DoH/DoT to encrypt queries.
* Rate-limit queries per client (e.g., iptables -j DNS_THROTTLE).

For Enterprises

* Monitor for DNS tunneling (e.g., Darktrace, Cisco Umbrella).
* Enforce registrar MFA (e.g., YubiKey for Cloudflare).

For Governments

* Mandate DNSSEC for critical TLDs (e.g., .gov, .bank).
* Share threat intel via FIRST/ICANN.

## Thoughts

DNS attacks are evolving in stealth and scale, from nation-state hijacking to IoT-powered DDoS. Proactive measures like 
DNSSEC, DoH, and aggressive monitoring are essential.
