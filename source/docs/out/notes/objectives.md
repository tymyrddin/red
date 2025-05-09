# The great heist: Knowing which nuts to crack

In 2025, the "Great Heist" represents the final phase of a cyberattack, where adversaries convert access, stolen data, 
or system control into financial gain, espionage value, or reputational damage. For red teams, understanding these 
monetization pathways is critical for simulating realistic threat scenarios. Below follows a break down of the latest 
tactics, dark web markets, and real-world case studies shaping cybercrime in 2025.

## Monetization pathways in 2025

Attackers leverage multiple methods to profit from compromised systems:

### Dark web data markets

Stolen data is sold on specialized dark web marketplaces, with pricing tiers based on freshness and completeness. 
This is pricing information, with both USD and EUR equivalents (using approximate 2025 exchange rates):

* Credit card dumps cost around $110 dollar (€100) per card with 5,000+ available balance.
* Corporate access credentials cost between $500−$2,000 (€450-€1,800) per set (VPN/RDP/cloud admin logins)
* Full identity packages cost $1,500+ (€1,350+) including SSNs, medical records, and biometric data

Top 2025 marketplaces:

* STYX Market: Focuses on financial crime (bank accounts, crypto wallets).
* Brian’s Club: Auctions bulk credit card data (10+ years in operation).
* BidenCash: Aggressively markets "free" data dumps to attract buyers.

Red Team Note: Simulate data sales by emulating listing formats (e.g., "Fresh 2025 EU Bank Logs – 70% Validity").

### Ransomware & extortion

With 35% fewer victims paying ransoms in 2024, attackers now combine:

* Encryption + Data theft: Exfiltrate data before deploying ransomware (e.g., LockBit 4.0).
* Triple extortion demands payment to:
  * Decrypt files.
  * Delete stolen data.
  * Avoid DDoS attacks on the victim’s public services.

Case Study: The Akira/Fog group extorted $75M from a single victim in 2024 by leaking snippets of proprietary AI code.

Red team playbook:

* Use RansomHub (a post-LockBit RaaS platform) for payload deployment.
* Negotiate via Tor-based chat portals (e.g., CipherStox).

### Cryptocurrency laundering

Post-payment, attackers use:

* Cross-chain bridges (e.g., YoMix) to obscure crypto trails 11.
* No-KYC exchanges: Though declining after German police seized 47 Russian platforms in 2024.

Red Team Tip: Trace payments using Chainalysis Reactor to simulate law enforcement tracking.

## Example Attack: 2025 hospital heist

Objective: Financial gain via ransomware + data resale.

### Attack Flow

1. Initial Access: Phishing email → CVE-2025-29824 (CLFS zero-day) exploit.
2. Lateral Movement: BloodHound maps AD → Compromises Veeam backups.
3. Data Harvesting:
   * Exfiltrates 500K patient records via DNS tunneling (DNSCat2).
   * Dumps NTLM hashes via Mimikatz (sekurlsa::logonpasswords).
4. Monetization:
   * Ransomware: Deploys MedusaLocker ($5M demand in Monero).
   * Dark Web Sale: Patient records auctioned on Russian Market for $200K.
5. Covering Tracks:
   * `wevtutil cl` security (clears logs).
   * Timestomping to evade forensic analysis.

## Red team recommendations

To emulate modern adversaries:

* Simulate hybrid attacks: Combine ransomware with data theft (e.g., exfiltrate dummy PII).
* Test Dark web interactions: Use closed Telegram channels (e.g., STYX Market’s invite-only groups) 3.
* Pressure extortion tactics: Threaten shareholder leaks if ransom is unpaid.

Toolkit:

* Mimikatz (credential harvesting).
* Rclone (data [exfiltration](exfiltration.md) to mock dark web servers).
* Cobalt Strike (ransomware deployment).

## 2025

The 2025 "Great Heist" landscape is defined by adaptability—attackers pivot between ransomware, dark web sales, and 
psychological extortion. Red teams must mirror these multi-stage monetization strategies to stress-test 
organizational defences effectively.
