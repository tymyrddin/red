# Nutcracker suite: leaving shells and chaos behind

Attackers may disrupt operations or destroy data to fulfill objectives like sabotage or ransom. This includes deploying 
ransomware, wiping systems, or altering critical files.

In 2025, cybercriminals and state-sponsored actors have refined data destruction and operational disruption techniques 
to maximize chaos, extortion payouts, or geopolitical sabotage. Below, we break down modern attack methods, including 
ransomware, disk-wiping, and critical system manipulation, along with a detailed real-world attack chain.

## AI-Enhanced ransomware

Adaptive Encryption: Ransomware like LockBit 4.0 uses machine learning to prioritize high-value files (e.g., 
databases, backups) while skipping non-critical data to speed up attacks.

Triple extortion encrypts files, steals data, and threatens DDoS attacks unless paid.

## Hybrid wiper-ransomware

Example: Blackout Worm (2024) first wipes backups using `shred -n 10 /dev/sdX`, then deploys ransomware to cripple 
recovery.

## Critical system manipulation

* SCADA/ICS Targeting: Attackers alter industrial control systems (e.g., water plants, power grids) to trigger physical failures.
* Database Wiping: SQL injection payloads like DROP TABLE or ransomware targeting Oracle/MS-SQL.

## Disk-wiping with advanced evasion

* Linux: `dd if=/dev/urandom of=/dev/sda` (overwrites disk with random data).
* Windows: "NukeBat" scripts use `cipher /w:C` (DoD-grade wipe) + disable recovery tools via:

```powershell
bcdedit /set {default} recoveryenabled no  
wbadmin delete catalog -quiet  
```

## Example: 2025 Healthcare Ransomware-Wiper Campaign

Attack Chain: MedusaLocker + Disk-Wiping

### Initial access

Phishing email with malicious ISO (disguised as a patient report) → Executes CVE-2025-29824 exploit (CLFS zero-day) to 
escalate privileges.

### Lateral movement

* Mimikatz harvests credentials → Moves via RDP to domain controllers.
* BloodHound maps AD → Targets backup servers (Veeam, Rubrik).

### Data destruction

* Step 1: `shred -n 5 -vz /dev/sdb1` (wipes backup storage).
* Step 2: Deploys MedusaLocker ransomware encrypting EHR databases with `.medusa` extension.

### Extortion

* Threaten to leak patient records unless paid money in Monero.
* DDoS overwhelms hospital portals during negotiations.

### Covering tracks

* `wevtutil cl` security (clears logs).
* Timestomping alters file metadata to hide activity.

## Defensive countermeasures

* Air-Gapped Backups: Isolate backups from networks.
* EDR with Behavioural AI: Detect `shred`/`dd` anomalies (e.g., SentinelOne).
* Zero Trust Segmentation: Limit lateral movement to critical systems.
* Patch CLFS Vulnerabilities: Mitigate CVE-2025-29824 exploits.

## 2025

In 2025 attackers combine ransomware, wipers, and critical system sabotage for maximum impact. Defenders must adopt 
AI-driven detection, immutable backups, and strict privilege controls to mitigate these threats.