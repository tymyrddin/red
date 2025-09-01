# The Double Bite

* Designation: APT-29 ("Midnight Sun")
* Target: Fungolian Government Department of Energy & Infrastructure
* Core TTPs: Phishing, VPN Exploitation, Credential Theft, Wiper Diversion
* Objective: Steal classified nuclear energy policy drafts and strategic communications, then deploy a destructive wiper to sabotage incident response and cover tracks.

## Phase 1: Initial Access – The Two-Pronged Attack

Goal: Breach the network with two independent methods to ensure at least one succeeds.

Narrative: You don't knock on just one door; you try the front and the back simultaneously. This "double tap" approach ensures entry even if one method is blocked.

The Attack Chain:

1.  Vector 1: The Spearphish (Social Engineering)
    *   The Lure: A highly targeted email is sent to a mid-level policy analyst in the Department of Energy. It appears to come from a trusted colleague at a nuclear research institute, referencing a real upcoming conference.
    *   The Payload: The email contains a PDF attachment titled "Draft_Agenda_Energy_Symposium.pdf". When opened, it exploits a known vulnerability in the PDF reader (e.g., CVE-2023-27333) to silently download and execute a Cobalt Strike Beacon—a powerful remote access tool that gives you a command line on the victim's computer.
    *   Why It Works: The email is personalised and relevant. The user's curiosity overrides caution.

2.  Vector 2: The VPN Exploit (Technical Intrusion)
    *   The Recon: Simultaneously, automated scanners probe the government's public-facing VPN gateway (e.g., a FortiGate SSL-VPN device).
    *   The Exploit: The scanners identify the device is running an outdated, vulnerable version. Using a publicly available exploit (e.g., for CVE-2024-21762), you execute malicious code on the VPN device itself.
    *   The Foothold: This provides a direct, unauthenticated entry point into the network's DMZ (a semi-trusted zone between the public internet and the internal network), completely bypassing the need for credentials.
    *   Why It Works: Patching critical internet-facing systems is often delayed due to complex change-control processes, leaving a known window of vulnerability.

## Phase 2: Establishing Footholds – Blending In

Goal: Secure persistent access points from both entry vectors.

Narrative: You're inside the building. Now you need to find a closet to hide in and make copies of the keys.

The Attack Chain:

*   From the Phish (Internal Workstation): The Cobalt Strike Beacon on the policy analyst's computer calls out to a attacker-controlled server, establishing a command & control (C2) channel. This gives you a presence on a trusted internal machine.
*   From the VPN (Network Device): The code executed on the VPN appliance creates a hidden backdoor account or a web shell, providing a separate, stealthy access point that looks like normal administrative traffic.

Stealth Tactics: Both channels use encrypted communication (HTTPS) to blend in with legitimate web traffic, making them very difficult to detect on the network.

## Phase 3: Privilege Escalation & Lateral Movement – The Keys to the Kingdom

Goal: Move from a basic user's computer to gaining control over the entire network.

Narrative: You have access to a single office. You need the master keycard that opens every door, especially the server room.

The Attack Chain:

1.  Credential Dumping (LSASS): From the compromised workstation, you use a tool like Mimikatz to dump passwords from the computer's memory (the LSASS process). This often reveals the logged-in user's password in plaintext.
2.  Pass-the-Hash: You use these stolen password "hashes" to authenticate to other systems, like internal file shares containing policy documents, without needing to know the actual password.
3.  Targeting Admins: You use your access to monitor network traffic, identifying IT administrators when they log in. You then target their workstations to dump *their* credentials.
4.  Domain Dominance: With an admin's credentials, you use Remote Desktop (RDP) to log directly into the Active Directory Domain Controller—the central server that manages all users and permissions for the entire organisation. You now own the network.

## Phase 4: Persistence – Building Secret Passageways

Goal: Ensure you can get back in even if your initial access points are discovered and closed.

The Attack Chain:

*   Scheduled Tasks: You create hidden tasks on multiple workstations to re-launch your backdoor every day at 3:00 AM.
*   Web Shells: You plant a simple, hidden web shell (a small PHP/ASPX file) on an internal SharePoint server. It looks like a normal web file but gives you a web-based command line if you access it with the right password.
*   Golden Tickets: From the Domain Controller, you can create forged authentication tickets that allow you to access any resource for long periods, even after passwords are changed.

## Phase 5: Command, Control, & Exfiltration – The Silent Heist

Goal: Steal the data without raising alarms.

The Attack Chain:

*   C2 Infrastructure: Your Cobalt Strike Beacons communicate with virtual private servers (VPS) hosted in another European country. This makes the traffic appear as normal EU internet activity.
*   Data Theft: You identify the file shares and mailboxes of senior officials. Using built-in system tools, you quietly compress the data (nuclear policy drafts, diplomatic emails) into encrypted RAR files.
*   Slow Exfiltration: You slowly trickle these files out over encrypted HTTPS connections, disguised as normal web browsing, to avoid triggering data loss prevention (DLP) systems that monitor for large data transfers.

## Phase 6: Cover Tracks – The Diversionary Fire

Goal: Sabotage the network to destroy evidence and distract incident responders from the theft.

Narrative: After the jewels are stolen, you start a fire. Everyone runs to put out the flames, not noticing the empty vault.

The Attack Chain:

*   Wiper Deployment: As the final exfiltration completes, you deploy a wiper malware (e.g., a variant of HermeticWiper) on a handful of critical workstations and servers.
*   How it Works: The wiper is designed to look like ransomware but its sole purpose is destruction. It overwrites the master boot record (MBR) and critical system files, rendering the machines completely unusable and unrecoverable without a full rebuild from backups.
*   The Distraction: Incident Response (IR) teams are activated urgently. The narrative becomes "We are under a destructive cyber attack!" The focus is entirely on containing the damage, restoring systems from backups, and investigating the *sabotage*. The silent, months-long theft of intelligence is completely overlooked.

The most sophisticated attacks are a marathon, not a sprint. The real damage is often the silent, long-term theft of secrets, while the visible destruction serves only to hide the theft. Defenders must learn to look beyond the smoke and mirrors.
